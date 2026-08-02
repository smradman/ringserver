/**************************************************************************
 * ring.c
 *
 * Fundamental ring routines.  This code implements a generic ring
 * buffer with the packet buffer either in memory or as a
 * memory-mapped file.
 *
 * The ring system is generally composed of 2 components: 1) a packet
 * buffer (either in memory or a mmap'd file) and 2) a stream index
 * stored as a binary tree.  If the packet buffer is to be stored in
 * memory the packet buffer file is read on startup and written on
 * shutdown only.  If the packet buffer is to be memory mapped the
 * packet buffer file will be used directly.  The stream index file is
 * read on startup and written on shutdown existing only in memory
 * during operation. The packet buffer (and related stream index) can
 * also be volatile, created in memory on initialization and lost on
 * program or ring shutdown.
 *
 * Ring writing is governed by a mutex to avoid writers colliding,
 * only one writer may modify the ring at a time.  Ring reading is
 * lockless with post-operation checking guaranteeing consistency.
 *
 * In general, non-existent packets are represented with a packet ID
 * of 0 and an offset of -1.
 *
 * This file is part of the ringserver.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (C) 2026:
 * @author Chad Trabant, EarthScope Data Services
 **************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libmseed.h>

#include "generic.h"
#include "logging.h"
#include "rbtree.h"
#include "ring.h"

/* Macros to determine next and previous packet offsets given an
 * reference offset, maximum offset, and packet size */
#define NEXTOFFSET(O, M, S) (((O) + (S) > (M)) ? 0 : (O) + (S))
#define PREVOFFSET(O, M, S) (((O) == 0) ? (M) : (O) - (S))

/* Macro to calculate pointer to RingPacket in buffer */
#define PACKETPTR(O) ((RingPacket *)(param.datastart + (O)))

/* Maximum bytes transferred per read()/write() call in ReadFull/WriteFull */
#define CHUNKIO_MAXCHUNK ((size_t)1 << 30) /* 1 GiB */

static int StreamIDCmp (const void *a, const void *b);
static int StreamIDSelected (RingReader *reader, const char *streamid);
static void SnapshotStreams (RBTree *tree, RBNode *node, RingStream *array,
                             uint32_t *count, uint32_t capacity);
static inline int64_t FindOffsetForID (uint64_t pktid, nstime_t *pkttime);
static RingStream *AddStreamIdx (RBTree *streamidx, RingStream *stream, Key **ppkey);
static RingStream *GetStreamIdx (RBTree *streamidx, char *streamid);
static int DelStreamIdx (RBTree *streamidx, char *streamid);
static int64_t ReadFull (int fd, uint8_t *buffer, uint64_t size);
static int64_t WriteFull (int fd, const uint8_t *buffer, uint64_t size);
static void FreeRingBuffer (void);

/***************************************************************************
 * LoadPktTime / StorePktTime:
 *
 * Access a RingPacket's pkttime field through a volatile pointer, forcing
 * an actual load/store rather than a value the compiler may have cached
 * or reordered.  RingPacket is packed, so atomic operations cannot be
 * used directly on the member; these are paired with explicit
 * memory_order_acquire/release fences for cross-thread ordering.
 *
 * The slot's pkttime acts as a single-writer sequence word: RingWrite()
 * stores NSTUNSET before mutating a slot's packet contents and stores the
 * real value as the final, single store after they are complete, so
 * lockless readers sampling NSTUNSET or a changed value know the slot
 * copy is not consistent.  Values are strictly increasing in ring order.
 * The nextinstream linkage field is maintained separately under the
 * writer locks and is not covered by this guard.
 *
 * The address is computed via offsetof to avoid taking the address of a
 * packed member; slots are 8-byte aligned (pktsize is rounded up), which
 * the single-copy atomicity of these accesses relies on.
 ***************************************************************************/
static inline nstime_t
LoadPktTime (const RingPacket *pkt)
{
  return *(const volatile nstime_t *)((const uint8_t *)pkt + offsetof (RingPacket, pkttime));
} /* End of LoadPktTime() */

static inline void
StorePktTime (RingPacket *pkt, nstime_t pkttime)
{
  *(volatile nstime_t *)((uint8_t *)pkt + offsetof (RingPacket, pkttime)) = pkttime;
} /* End of StorePktTime() */

/***************************************************************************
 * ReadFull / WriteFull:
 *
 * Transfer exactly size bytes between a file descriptor and a memory
 * buffer, looping in chunks of at most CHUNKIO_MAXCHUNK bytes since a
 * single read()/write() call is not guaranteed to transfer more than
 * that in one call (notably for sizes at or beyond 2 GiB).
 *
 * Return the number of bytes transferred on success (always size) or
 * -1 on error or short (0 or negative) transfer.
 ***************************************************************************/
static int64_t
ReadFull (int fd, uint8_t *buffer, uint64_t size)
{
  uint64_t total = 0;
  ssize_t nread;
  size_t chunk;

  while (total < size)
  {
    chunk = (size - total > CHUNKIO_MAXCHUNK) ? CHUNKIO_MAXCHUNK : (size_t)(size - total);
    nread = read (fd, buffer + total, chunk);

    if (nread < 0 && errno == EINTR)
      continue;

    if (nread == 0)
      errno = EIO; /* Short transfer, ensure a sensible errno for callers */

    if (nread <= 0)
      return -1;

    total += (uint64_t)nread;
  }

  return (int64_t)total;
} /* End of ReadFull() */

static int64_t
WriteFull (int fd, const uint8_t *buffer, uint64_t size)
{
  uint64_t total = 0;
  ssize_t nwritten;
  size_t chunk;

  while (total < size)
  {
    chunk    = (size - total > CHUNKIO_MAXCHUNK) ? CHUNKIO_MAXCHUNK : (size_t)(size - total);
    nwritten = write (fd, buffer + total, chunk);

    if (nwritten < 0 && errno == EINTR)
      continue;

    if (nwritten == 0)
      errno = EIO; /* Short transfer, ensure a sensible errno for callers */

    if (nwritten <= 0)
      return -1;

    total += (uint64_t)nwritten;
  }

  return (int64_t)total;
} /* End of WriteFull() */

/***************************************************************************
 * FreeRingBuffer:
 *
 * Release the ring packet buffer allocated in param.ringbuffer, either
 * unmapping or freeing it depending on how it was obtained, and reset
 * the pointer to NULL.
 ***************************************************************************/
static void
FreeRingBuffer (void)
{
  if (config.memorymapring && !config.volatilering)
  {
    if (munmap ((void *)param.ringbuffer, config.ringsize))
    {
      lprintf (0, "%s(): error unmapping ring file: %s", __func__, strerror (errno));
    }
  }
  else
  {
    free (param.ringbuffer);
  }
  param.ringbuffer = NULL;
} /* End of FreeRingBuffer() */

/***************************************************************************
 * RingInitialize:
 *
 * Initialize ring buffer files either loading and validating the existing
 * ring buffer files or creating new files.
 *
 * ring file = main packet buffer file, optionally memory mapped
 * stream file = stream index file, loaded into param.streamidx
 *
 * Return >0 on buffer version mismatch, the version number is returned
 * Return  0 on success
 * Return -1 on corruption errors
 * Return -2 on non-recoverable errors
 ***************************************************************************/
int
RingInitialize (char *ringfilename, char *streamfilename, int *ringfd)
{
  struct stat ringfilestat;
  struct stat streamfilestat;
  int streamidxfd;
  RingStream stream;

  long pagesize;
  uint32_t headersize;
  uint64_t maxpackets;
  int64_t maxoffset;
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;

  int corruptring = 0;
  int ringinit    = 0;
  int replacing   = 0;
  uint16_t ring_version;
  ssize_t rv;
  RingPacket *packetptr;
  RingStream *streamptr;

  /* Sanity check input parameters */
  if (!config.volatilering && (!ringfilename || !streamfilename))
  {
    lprintf (0, "%s(): ring file and stream file must be specified", __func__);
    return -2;
  }

  /* A volatile ring will never be memory mapped */
  if (config.volatilering)
  {
    config.memorymapring = 0;
  }

  /* Determine system page size */
  if ((pagesize = sysconf (_SC_PAGESIZE)) < 0)
  {
    lprintf (0, "%s(): Error determining system page size: %s",
             __func__, strerror (errno));
    return -2;
  }

  /* Determine the number of pages needed for the header, for alignment of data packets */
  headersize = pagesize;
  while (headersize < RBV3_HEADERSIZE)
    headersize += pagesize;

  /* Sanity check that the ring can hold at least two packets */
  if (config.ringsize < (headersize + 2 * config.pktsize))
  {
    lprintf (0, "%s(): ring size (%" PRIu64 ") must be enough for 2 packets (%u each) and header (%d)",
             __func__, config.ringsize, config.pktsize, headersize);
    return -2;
  }

  /* Determine the maximum number of packets that fit after the first page */
  maxpackets = (uint64_t)((config.ringsize - headersize) / config.pktsize);

  /* Determine the maximum packet offset value */
  maxoffset = (int64_t)((maxpackets - 1) * config.pktsize);

  /* Open ring packet buffer file if non-volatile */
  if (!config.volatilering)
  {
    /* Open ring packet buffer file, creating if necessary */
    if ((*ringfd = open (ringfilename, O_RDWR | O_CREAT, mode)) < 0)
    {
      lprintf (0, "%s(): error opening %s: %s", __func__, ringfilename, strerror (errno));
      return -1;
    }

    /* Stat the ring packet buffer file */
    if (fstat (*ringfd, &ringfilestat))
    {
      lprintf (0, "%s(): error stating %s: %s", __func__, ringfilename, strerror (errno));
      return -1;
    }

    /* Pre-check: detect rebuildable V3 parameter changes before modifying the file */
    if (ringfilestat.st_size > 0)
    {
      char header[RBV3_HEADERSIZE];
      if (pread (*ringfd, header, RBV3_HEADERSIZE, 0) == RBV3_HEADERSIZE &&
          memcmp (pRBV3_SIGNATURE (header), RING_SIGNATURE, RING_SIGNATURE_LENGTH) == 0 &&
          *pRBV3_VERSION (header) == RING_VERSION)
      {
        uint64_t old_ringsize;
        uint32_t old_pktsize;
        uint32_t old_headersize;
        memcpy (&old_ringsize, pRBV3_RINGSIZE (header), 8);
        memcpy (&old_pktsize, pRBV3_PKTSIZE (header), 4);
        memcpy (&old_headersize, pRBV3_HEADERSIZE (header), 4);

        if (old_ringsize != config.ringsize || old_pktsize != config.pktsize ||
            old_headersize != headersize)
        {
          if (old_pktsize <= config.pktsize)
          {
            /* Report changes and signal rebuild */
            if (old_ringsize != config.ringsize)
              lprintf (0, "** Packet buffer size change: %" PRIu64 " -> %" PRIu64,
                       old_ringsize, config.ringsize);
            if (old_pktsize != config.pktsize)
              lprintf (0, "** Packet size change: %u -> %u", old_pktsize, config.pktsize);
            if (old_headersize != headersize)
              lprintf (0, "** Header size change: %u -> %u", old_headersize, headersize);
            lprintf (0, "Ring buffer can be rebuilt with new parameters");
            return RING_VERSION;
          }
          else
          {
            lprintf (0, "** MaxPacketSize decreased (%u -> %u), cannot rebuild, data will be discarded",
                     old_pktsize, config.pktsize);
            /* Fall through to existing reset behavior */
          }
        }
      }
    }

    /* If the file is new or unexpected size initialize to maximum ring file size */
    if (ringfilestat.st_size != config.ringsize)
    {
      ringinit = 1;

      if (ringfilestat.st_size <= 0)
        lprintf (1, "Creating new ring packet buffer file");
      else
      {
        lprintf (1, "Re-creating ring packet buffer file");
        replacing = 1;
      }

      /* Truncate file if larger than ringsize */
      if (ringfilestat.st_size > config.ringsize)
      {
        if (ftruncate (*ringfd, (off_t)config.ringsize) == -1)
        {
          lprintf (0, "%s(): error truncating %s: %s", __func__, ringfilename, strerror (errno));
          return -1;
        }
      }

      /* Go to the last byte of the desired size */
      if (lseek (*ringfd, (off_t)config.ringsize - 1, SEEK_SET) == -1)
      {
        lprintf (0, "%s(): error seeking in %s: %s", __func__, ringfilename, strerror (errno));
        return -1;
      }

      /* Write a dummy byte at the end of the ring packet buffer */
      if (write (*ringfd, "", 1) != 1)
      {
        lprintf (0, "%s(): error writing to %s: %s", __func__, ringfilename, strerror (errno));
        return -1;
      }
    }
    else
    {
      lprintf (1, "Recovering existing ring packet buffer file");
    }
  }

  /* Use memory-mapping to access file */
  if (config.memorymapring && !config.volatilering)
  {
    lprintf (1, "Memory-mapping ring packet buffer file");

    /* Memory map the ring packet buffer file */
    if ((param.ringbuffer = (uint8_t *)mmap (NULL, config.ringsize, PROT_READ | PROT_WRITE,
                                             MAP_SHARED, *ringfd, 0)) == MAP_FAILED)
    {
      lprintf (0, "%s(): error mmaping %s: %s", __func__, ringfilename, strerror (errno));
      return -1;
    }

    /* Hint sequential access pattern: reduces page-fault stalls on the write
     * path and encourages early writeback of dirty pages by the kernel */
#if defined(MADV_SEQUENTIAL)
    madvise (param.ringbuffer, config.ringsize, MADV_SEQUENTIAL);
#endif
  }
  /* Read ring packet buffer into memory if not memory-mapping. */
  else
  {
    lprintf (2, "Allocating ring packet buffer memory");

    /* Allocate ring packet buffer */
    if (!(param.ringbuffer = malloc (config.ringsize)))
    {
      lprintf (0, "%s(): error allocating %" PRIu64 " bytes for ring packet buffer",
               __func__, config.ringsize);
      return -2;
    }

    /* Force ring initialization if volatile */
    if (config.volatilering)
      ringinit = 1;

    /* Read ring packet buffer into memory if initialization is not needed */
    if (!ringinit)
    {
      lprintf (1, "Reading ring packet buffer file into memory");

      if (ReadFull (*ringfd, param.ringbuffer, config.ringsize) != (int64_t)config.ringsize)
      {
        lprintf (0, "%s(): error reading ring packet buffer into memory: %s",
                 __func__, strerror (errno));
        FreeRingBuffer ();
        return -1;
      }
    }
  }

  /* If signature match but version mismatch return current buffer version */
  if (!ringinit &&
      memcmp (pRBV3_SIGNATURE (param.ringbuffer), RING_SIGNATURE, RING_SIGNATURE_LENGTH) == 0 &&
      *pRBV3_VERSION (param.ringbuffer) != RING_VERSION)
  {
    ring_version = *pRBV3_VERSION (param.ringbuffer);
    lprintf (0, "Packet buffer version %u detected", ring_version);
    FreeRingBuffer ();
    return ring_version;
  }

  /* Initialize volatile ring packet buffer parameters */
  if ((param.streamidx = RBTreeCreate (KeyCompare, free, free)) == NULL)
  {
    lprintf (0, "%s(): error allocating stream index tree", __func__);
    FreeRingBuffer ();
    return -1;
  }
  param.datastart = param.ringbuffer + headersize;

  /* Load parameters from stored header */
  memcpy (&param.version, pRBV3_VERSION (param.ringbuffer), 2);
  memcpy (&param.ringsize, pRBV3_RINGSIZE (param.ringbuffer), 8);
  memcpy (&param.pktsize, pRBV3_PKTSIZE (param.ringbuffer), 4);
  memcpy (&param.maxpackets, pRBV3_MAXPACKETS (param.ringbuffer), 8);
  memcpy (&param.maxoffset, pRBV3_MAXOFFSET (param.ringbuffer), 8);
  memcpy (&param.headersize, pRBV3_HEADERSIZE (param.ringbuffer), 4);
  memcpy (&param.earliestoffset, pRBV3_EARLIESTOFFSET (param.ringbuffer), 8);
  memcpy (&param.latestoffset, pRBV3_LATESTOFFSET (param.ringbuffer), 8);

  /* Validate existing ring packet buffer parameters, resetting if needed */
  if (ringinit ||
      memcmp (pRBV3_SIGNATURE (param.ringbuffer), RING_SIGNATURE, RING_SIGNATURE_LENGTH) ||
      param.version != RING_VERSION ||
      param.ringsize != config.ringsize ||
      param.pktsize != config.pktsize ||
      param.maxpackets != maxpackets ||
      param.maxoffset != maxoffset ||
      param.headersize != headersize)
  {
    /* Report what triggered the parameter reset if not just initialized */
    if (!ringinit)
    {
      replacing = 1;

      if (memcmp (pRBV3_SIGNATURE (param.ringbuffer), RING_SIGNATURE, RING_SIGNATURE_LENGTH))
        lprintf (0, "** Packet buffer signature mismatch: %.4s <-> %.4s", pRBV3_SIGNATURE (param.ringbuffer), RING_SIGNATURE);
      if (param.version != RING_VERSION)
        lprintf (0, "** Packet buffer version change: %u -> %u", param.version, RING_VERSION);
      if (param.ringsize != config.ringsize)
        lprintf (0, "** Packet buffer size change: %" PRIu64 " -> %" PRIu64, param.ringsize, config.ringsize);
      if (param.pktsize != config.pktsize)
        lprintf (0, "** Packet size change: %u -> %u", param.pktsize, config.pktsize);
      if (param.maxpackets != maxpackets)
        lprintf (0, "** Maximum packets change: %" PRIu64 " -> %" PRIu64, param.maxpackets, maxpackets);
      if (param.maxoffset != maxoffset)
        lprintf (0, "** Maximum offset change: %" PRId64 " -> %" PRId64, param.maxoffset, maxoffset);
      if (param.headersize != headersize)
        lprintf (0, "** Header size change: %u -> %u", param.headersize, headersize);
    }

    if (replacing)
      lprintf (0, "Resetting ring packet buffer, contents are discarded");

    param.version        = RING_VERSION;
    param.ringsize       = config.ringsize;
    param.pktsize        = config.pktsize;
    param.maxpackets     = maxpackets;
    param.maxoffset      = maxoffset;
    param.headersize     = headersize;
    param.earliestoffset = -1;
    param.latestoffset   = -1;

    /* Clear unused header space */
    memset (param.ringbuffer + RBV3_HEADERSIZE, 0, headersize - RBV3_HEADERSIZE);
  }
  /* If the ring has not been reset and packets are present recover stream index */
  else if (param.earliestoffset >= 0)
  {
    lprintf (1, "Recovering stream index");

    /* Open stream index file */
    if ((streamidxfd = open (streamfilename, O_RDONLY, 0)) < 0)
    {
      lprintf (0, "%s(): error opening %s: %s", __func__, streamfilename, strerror (errno));
      RBTreeDestroy (param.streamidx);
      param.streamidx = NULL;
      FreeRingBuffer ();
      return -1;
    }

    /* Stat the streams file */
    if (fstat (streamidxfd, &streamfilestat))
    {
      lprintf (0, "%s(): error stating %s: %s", __func__, streamfilename, strerror (errno));
      close (streamidxfd);
      RBTreeDestroy (param.streamidx);
      param.streamidx = NULL;
      FreeRingBuffer ();
      return -1;
    }

    if (streamfilestat.st_size > 0)
    {
      /* Read the saved RingStreams */
      while ((rv = read (streamidxfd, &stream, sizeof (RingStream))) == sizeof (RingStream))
      {
        /* Re-populating streams index */
        if (!AddStreamIdx (param.streamidx, &stream, 0))
        {
          lprintf (0, "%s(): error adding stream to index", __func__);
          corruptring = 1;
        }
        else
        {
          param.streamcount++;
        }
      }

      /* Test for read error */
      if (rv < 0)
      {
        lprintf (0, "%s(): error reading %s: %s", __func__, streamfilename, strerror (errno));
        close (streamidxfd);
        RBTreeDestroy (param.streamidx);
        param.streamidx = NULL;
        FreeRingBuffer ();
        return -1;
      }
    }
    else
    {
      lprintf (0, "%s(): stream index file empty!", __func__);
      close (streamidxfd);
      RBTreeDestroy (param.streamidx);
      param.streamidx = NULL;
      FreeRingBuffer ();
      return -1;
    }

    /* Close the stream index file and release file name memory */
    close (streamidxfd);
  }

  if (param.earliestoffset > param.maxoffset)
  {
    lprintf (0, "%s(): error earliest offset > maxoffset, ring corrupted", __func__);
    corruptring = 1;
  }
  if (param.latestoffset > param.maxoffset)
  {
    lprintf (0, "%s(): error latest offset > maxoffset, ring corrupted", __func__);
    corruptring = 1;
  }

  /* Sanity checks: compare earliest and latest packet offsets between ring params
   * and lookups and check the earliest and latest stream entries. */
  if (!corruptring && param.earliestoffset >= 0)
  {
    packetptr = PACKETPTR (param.earliestoffset);

    if (packetptr->offset != param.earliestoffset)
    {
      lprintf (0, "%s(): error comparing earliest packet offsets, ring corrupted", __func__);
      corruptring = 1;
    }
    else if (!(streamptr = GetStreamIdx (param.streamidx, packetptr->streamid)))
    {
      lprintf (0, "%s(): error finding stream entry for earliest packet, ring corrupted", __func__);
      corruptring = 1;
    }
  }
  if (!corruptring && param.latestoffset >= 0)
  {
    packetptr = PACKETPTR (param.latestoffset);

    if (packetptr->offset != param.latestoffset)
    {
      lprintf (0, "%s(): error comparing latest packet offsets, ring corrupted", __func__);
      corruptring = 1;
    }
    else if (!(streamptr = GetStreamIdx (param.streamidx, packetptr->streamid)))
    {
      lprintf (0, "%s(): error finding stream entry for latest packet, ring corrupted", __func__);
      corruptring = 1;
    }
  }

  /* If corruption was detected cleanup before returning */
  if (corruptring)
  {
    RBTreeDestroy (param.streamidx);
    param.streamidx = NULL;
    FreeRingBuffer ();

    /* Close the ring file and re-init the descriptor */
    if (close (*ringfd))
    {
      lprintf (0, "%s(): error closing ring file: %s", __func__, strerror (errno));
    }
    *ringfd = -1;

    return -1;
  }

  lprintf (0, "Ring initialized");

  return 0;
} /* End of RingInitialize() */

/***************************************************************************
 * RingShutdown:
 *
 * Perform shutdown procedures for the ring buffer.
 *
 * After the write lock of the mmap'd ring has been obtained the
 * streams index is written to streamfilename and the ring is either
 * unmapped or written to the open ringfd and closed.
 *
 * Returns 0 on success, and -1 on failure
 ***************************************************************************/
int
RingShutdown (int ringfd, char *streamfilename)
{
  int streamidxfd;
  int rc;
  int rv = 0;
  Stack *streams;
  RingStream *stream;

  RBNode *tnode;
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;

  if (!config.volatilering && (ringfd < 0 || !streamfilename))
    return -1;

  /* Free memory and return if ring is volatile */
  if (config.volatilering)
  {
    RBTreeDestroy (param.streamidx);
    free (param.ringbuffer);
    return 0;
  }

  /* Open stream index file */
  if ((streamidxfd = open (streamfilename, O_RDWR | O_CREAT | O_TRUNC, mode)) < 0)
  {
    lprintf (0, "%s(): error opening %s: %s", __func__, streamfilename, strerror (errno));
    rv = -1;
  }

  /* Lock ring and stream against writes, destroyed later */
  pthread_mutex_lock (&param.ringlock);
  pthread_mutex_lock (&param.streamlock);

  /* Create Stack of RingStreams */
  streams = StackCreate ();
  RBBuildStack (param.streamidx, streams);

  /* Write RingStreams to stream index file */
  if (streamidxfd >= 0)
  {
    lprintf (1, "Writing stream index file");
    while ((tnode = (RBNode *)StackPop (streams)))
    {
      stream = (RingStream *)tnode->data;

      if (write (streamidxfd, stream, sizeof (RingStream)) != sizeof (RingStream))
      {
        lprintf (0, "%s(): error writing to %s: %s", __func__, streamfilename, strerror (errno));
        rv = -1;
      }
    }

    /* Close the streams file */
    if (close (streamidxfd))
    {
      lprintf (0, "%s(): error closing %s: %s", __func__, streamfilename, strerror (errno));
      rv = -1;
    }
  }

  /* Cleanup stream index related memory */
  RBTreeDestroy (param.streamidx);
  StackDestroy (streams, 0);
  param.streamidx = NULL;

  /* Destroy streams index lock */
  pthread_mutex_unlock (&param.streamlock);
  if ((rc = pthread_mutex_destroy (&param.streamlock)))
  {
    lprintf (0, "%s(): error destroying stream lock: %s", __func__, strerror (rc));
    rv = -1;
  }

  memset (param.ringbuffer, 0, RBV3_HEADERSIZE);

  /* Store the header values in the ring buffer */
  memcpy (pRBV3_SIGNATURE (param.ringbuffer), RING_SIGNATURE, RING_SIGNATURE_LENGTH);
  memcpy (pRBV3_VERSION (param.ringbuffer), &param.version, 2);
  memcpy (pRBV3_RINGSIZE (param.ringbuffer), &param.ringsize, 8);
  memcpy (pRBV3_PKTSIZE (param.ringbuffer), &param.pktsize, 4);
  memcpy (pRBV3_MAXPACKETS (param.ringbuffer), &param.maxpackets, 8);
  memcpy (pRBV3_MAXOFFSET (param.ringbuffer), &param.maxoffset, 8);
  memcpy (pRBV3_HEADERSIZE (param.ringbuffer), &param.headersize, 4);
  memcpy (pRBV3_EARLIESTOFFSET (param.ringbuffer), &param.earliestoffset, 8);
  memcpy (pRBV3_LATESTOFFSET (param.ringbuffer), &param.latestoffset, 8);

  if (config.memorymapring)
  {
    /* Unmap the ring buffer file */
    lprintf (1, "Unmapping and closing ring buffer file");
    if (munmap ((void *)param.ringbuffer, param.ringsize))
    {
      lprintf (0, "%s(): error unmapping ring buffer file: %s", __func__, strerror (errno));
      rv = -1;
    }

    /* Destroy ring write lock */
    pthread_mutex_unlock (&param.ringlock);
    if ((rc = pthread_mutex_destroy (&param.ringlock)))
    {
      lprintf (0, "%s(): error destroying ring write lock: %s", __func__, strerror (rc));
      rv = -1;
    }
  }
  else
  {
    /* Write the ring buffer file */
    lprintf (1, "Writing and closing ring buffer file");

    if (lseek (ringfd, 0, SEEK_SET) == -1)
    {
      lprintf (0, "%s(): error seeking in ring buffer file: %s", __func__, strerror (errno));
      rv = -1;
    }

    if (WriteFull (ringfd, param.ringbuffer, param.ringsize) != (int64_t)param.ringsize)
    {
      lprintf (0, "%s(): error writing ring buffer file: %s", __func__, strerror (errno));
      rv = -1;
    }

    /* Destroy ring write lock */
    pthread_mutex_unlock (&param.ringlock);
    if ((rc = pthread_mutex_destroy (&param.ringlock)))
    {
      lprintf (0, "%s(): error destroying ring write lock: %s", __func__, strerror (rc));
      rv = -1;
    }

    /* Free the ring buffer memory */
    free (param.ringbuffer);
    param.ringbuffer = NULL;
  }

  /* Close the ring file */
  if (close (ringfd))
  {
    lprintf (0, "%s(): error closing ring buffer file: %s", __func__, strerror (errno));
    rv = -1;
  }

  return rv;
} /* End of RingShutdown() */

/***************************************************************************
 * RingWrite:
 *
 * Add packet to the ring including updates to the packet and stream
 * indexes.
 *
 * This routine will set the pktid, offset, pkttime, nextpacket and
 * nextstream values for the packet after they are determined.  If
 * this routine fails after starting to modify the ring constructs the
 * ring will almost certainly be out of sync and should be considered
 * corrupt, this is indicated with a return value of -2.
 *
 * Returns 0 on success, -1 on non-corruption error and -2 on corrupt
 * ring error.
 ***************************************************************************/
int
RingWrite (RingPacket *packet, char *packetdata, uint32_t datasize)
{
  RingStream *stream;
  RingStream newstream;
  RingPacket *earliest = NULL;
  RingPacket *latest   = NULL;
  RingPacket *prevlatest;
  Key *skey;

  uint64_t pktid;
  int64_t offset;
  int64_t earliestoffset;
  int64_t latestoffset;
  nstime_t pkttime;

  /* Last stamped packet creation time, protected by ringlock */
  static nstime_t last_pkttime = 0;

  /* Details captured for log messages emitted after the locks are released */
  int log_removed_packet = 0;
  char removedpkt_streamid[MAXSTREAMID];
  uint64_t removedpkt_pktid = 0;
  int64_t removedpkt_offset = 0;
  int log_removed_stream    = 0;
  char removedstream_streamid[MAXSTREAMID];
  int log_added_stream = 0;
  char addedstream_streamid[MAXSTREAMID];
  uint64_t addedstream_key = 0;

  if (!packet || !packetdata)
    return -1;

  /* Ensure the caller-supplied stream ID is NUL-terminated before it is
   * used for hashing and lookup */
  packet->streamid[MAXSTREAMID - 1] = '\0';

  /* Check packet size */
  if ((sizeof (RingPacket) + datasize) > param.pktsize)
  {
    lprintf (0, "%s(): %s packet size too large (%zu), maximum is %u bytes",
             __func__, packet->streamid, (sizeof (RingPacket) + datasize), param.pktsize);
    return -1;
  }

  packet->datasize = datasize;

  /* Lock ring and streams index */
  pthread_mutex_lock (&param.ringlock);
  pthread_mutex_lock (&param.streamlock);

  /* Stamp the packet creation time under the lock and force it to be
   * strictly increasing: it doubles as the sequence word for lockless
   * readers, which requires unique, monotonic values in ring order. */
  pkttime = NSnow ();
  if (pkttime <= last_pkttime)
    pkttime = last_pkttime + 1;
  last_pkttime = pkttime;

  earliestoffset = param.earliestoffset;
  latestoffset   = param.latestoffset;

  /* Set packet entries for earliest and latest packets in ring */
  if (earliestoffset >= 0)
  {
    earliest = PACKETPTR (earliestoffset);
  }
  if (latestoffset >= 0)
  {
    latest = PACKETPTR (latestoffset);
  }

  /* Determine next packet offset and ID */
  if (latest)
  {
    offset = NEXTOFFSET (latest->offset, param.maxoffset, config.pktsize);
    pktid  = latest->pktid + 1;

    /* In the unlikely event we reached the end of the universe start again with 1 */
    if (pktid > RINGID_MAXIMUM)
    {
      pktid = 1;
    }
  }
  /* Otherwise the buffer is empty, start from the beginning */
  else
  {
    offset = 0;
    pktid  = 1;
  }

  /* Remove earliest packet if ring is full (target offset == earliest) */
  if (earliest && latest && earliest != latest &&
      offset == earliestoffset)
  {
    int64_t next_offset;                 /* New earliest packet offset */
    RingPacket *nextInRing       = NULL; /* New earliest packet in ring */
    RingPacket *nextInStream     = NULL; /* New earliest packet in stream */
    RingStream *streamOfEarliest = NULL; /* Stream of old earliest packet */

    next_offset  = NEXTOFFSET (earliest->offset, param.maxoffset, config.pktsize);
    nextInRing   = PACKETPTR (next_offset);
    nextInStream = (earliest->nextinstream >= 0) ? PACKETPTR (earliest->nextinstream) : NULL;

    /* Update global params with new earliest entry */
    param.earliestoffset = nextInRing->offset;

    /* Capture details for the "removing packet" log message, emitted after
     * the locks are released below.  The in-ring stream ID is not
     * guaranteed to be NUL-terminated. */
    log_removed_packet = 1;
    memcpy (removedpkt_streamid, earliest->streamid, sizeof (removedpkt_streamid));
    removedpkt_streamid[sizeof (removedpkt_streamid) - 1] = '\0';

    removedpkt_pktid  = earliest->pktid;
    removedpkt_offset = earliest->offset;

    if (!(streamOfEarliest = GetStreamIdx (param.streamidx, earliest->streamid)))
    {
      pthread_mutex_unlock (&param.ringlock);
      pthread_mutex_unlock (&param.streamlock);
      lprintf (3, "Removing packet for stream %s (id: %" PRIu64 ", offset: %" PRId64 ")",
               removedpkt_streamid, removedpkt_pktid, removedpkt_offset);
      lprintf (0, "%s(): Error getting earliest packet stream", __func__);
      return -2;
    }

    /* Delete stream entry if this is the only packet */
    if (earliest->offset == streamOfEarliest->earliestoffset &&
        earliest->offset == streamOfEarliest->latestoffset)
    {
      if (DelStreamIdx (param.streamidx, earliest->streamid) == 0)
      {
        param.streamcount--;
        log_removed_stream = 1;
        memcpy (removedstream_streamid, earliest->streamid, sizeof (removedstream_streamid));
        removedstream_streamid[sizeof (removedstream_streamid) - 1] = '\0';
      }
      else
      {
        lprintf (0, "%s(): Error removing stream index entry for %s", __func__, earliest->streamid);
      }
    }
    /* Else update stream entry for the next packet in the stream */
    else if (nextInStream)
    {
      streamOfEarliest->earliestdstime = nextInStream->datastart;
      streamOfEarliest->earliestdetime = nextInStream->dataend;
      streamOfEarliest->earliestptime  = nextInStream->pkttime;
      streamOfEarliest->earliestid     = nextInStream->pktid;
      streamOfEarliest->earliestoffset = nextInStream->offset;
    }
  }

  /* Update new packet details */
  packet->pktid        = (packet->pktid == RINGID_NONE) ? pktid : packet->pktid;
  packet->offset       = offset;
  packet->pkttime      = pkttime;
  packet->nextinstream = -1;

  /* Find RingStream entry, creating if not found */
  if (!(stream = GetStreamIdx (param.streamidx, packet->streamid)))
  {
    /* Populate and add RingStream entry */
    memset (&newstream, 0, sizeof (RingStream));
    memcpy (newstream.streamid, packet->streamid, sizeof (newstream.streamid));
    newstream.earliestdstime = packet->datastart;
    newstream.earliestdetime = packet->dataend;
    newstream.earliestptime  = packet->pkttime;
    newstream.earliestid     = packet->pktid;
    newstream.earliestoffset = packet->offset;
    newstream.latestoffset   = -1;
    /* The "latest" fields are populated later */

    /* Add new stream to index */
    if (!(stream = AddStreamIdx (param.streamidx, &newstream, &skey)))
    {
      pthread_mutex_unlock (&param.ringlock);
      pthread_mutex_unlock (&param.streamlock);
      if (log_removed_packet)
        lprintf (3, "Removing packet for stream %s (id: %" PRIu64 ", offset: %" PRId64 ")",
                 removedpkt_streamid, removedpkt_pktid, removedpkt_offset);
      if (log_removed_stream)
        lprintf (2, "Removing stream index entry for %s", removedstream_streamid);
      lprintf (0, "%s(): Error adding new stream index", __func__);
      return -2;
    }
    else
    {
      param.streamcount++;
      log_added_stream = 1;
      memcpy (addedstream_streamid, packet->streamid, sizeof (addedstream_streamid));
      addedstream_key = *skey;
    }
  }

  /* Mark the slot as mid-write by invalidating its pkttime so lockless
   * readers sampling it know the contents are not consistent */
  RingPacket *slotpkt = PACKETPTR (offset);
  StorePktTime (slotpkt, NSTUNSET);
  atomic_thread_fence (memory_order_release);

  /* Copy packet data into the ring, directly after the header slot */
  uint8_t *writeptr = (uint8_t *)slotpkt;
  memcpy ((writeptr + sizeof (RingPacket)), packetdata, datasize);

  /* Copy packet header into the ring with pkttime withheld (still
   * NSTUNSET), keeping the slot marked mid-write: a bulk copy provides no
   * ordering of the sequence word relative to the other header bytes */
  packet->pkttime = NSTUNSET;
  memcpy (writeptr, packet, sizeof (RingPacket));
  packet->pkttime = pkttime;

  /* Publish: ensure all slot contents are visible before the single,
   * final store of the real pkttime re-validates the slot for readers */
  atomic_thread_fence (memory_order_release);
  StorePktTime (slotpkt, pkttime);

  /* Update entry for previous packet in stream */
  if (stream->latestoffset >= 0)
  {
    prevlatest = PACKETPTR (stream->latestoffset);

    prevlatest->nextinstream = packet->offset;
  }

  /* Update stream entry */
  stream->latestdstime = packet->datastart;
  stream->latestdetime = packet->dataend;
  stream->latestptime  = packet->pkttime;
  stream->latestid     = packet->pktid;
  stream->latestoffset = packet->offset;

  /* Update ring params with new earliest packet (for initial packet) */
  if (!earliest)
  {
    param.earliestoffset = packet->offset;
  }

  /* Update ring params with new latest packet
   * Ensure all updates are visibile before updating latestoffset */
  param.latestoffset = packet->offset;

  /* Unlock ring and stream index */
  pthread_mutex_unlock (&param.ringlock);
  pthread_mutex_unlock (&param.streamlock);

  /* Emit log messages for events captured above, now that the locks are
   * released and writers/readers are no longer serialized behind them */
  if (log_removed_packet)
    lprintf (3, "Removing packet for stream %s (id: %" PRIu64 ", offset: %" PRId64 ")",
             removedpkt_streamid, removedpkt_pktid, removedpkt_offset);

  if (log_removed_stream)
    lprintf (2, "Removing stream index entry for %s", removedstream_streamid);

  if (log_added_stream)
    lprintf (2, "Added stream entry for %s (key: %" PRIx64 ")", addedstream_streamid, addedstream_key);

  lprintf (3, "Added packet for stream %s, pktid: %" PRIu64 ", offset: %" PRId64,
           packet->streamid, packet->pktid, packet->offset);

  return 0;
} /* End of RingWrite() */

/***************************************************************************
 * RingReadPacket:
 *
 * Read a packet from a specified offset.
 *
 * The packet pointer must point to already allocated memory.
 *
 * The packet data will only be returned if the packetdata pointer is not
 * NULL and points to already allocated memory.
 *
 * Returns the packet ID on success, RINGID_NONE when the packet was not
 * found and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingReadPacket (int64_t offset, RingPacket *packet, char *packetdata)
{
  RingPacket *pkt;
  nstime_t pkttime;
  uint32_t maxpayload;

  if (!packet)
    return RINGID_ERROR;

  if (offset < 0)
  {
    return RINGID_NONE;
  }

  if (offset > param.maxoffset)
  {
    lprintf (0, "%s(): offset value beyond maximum: %" PRId64, __func__, offset);
    return RINGID_ERROR;
  }

  pkt = PACKETPTR (offset);

  /* Sample pkttime, then copy the packet, then re-check pkttime below to
   * detect a concurrent RingWrite() overwriting this slot.  NSTUNSET
   * means the slot is mid-write. */
  pkttime = LoadPktTime (pkt);
  atomic_thread_fence (memory_order_acquire);

  if (pkttime == NSTUNSET)
  {
    return RINGID_NONE;
  }

  /* Copy packet header */
  memcpy (packet, pkt, sizeof (RingPacket));
  packet->streamid[MAXSTREAMID - 1] = '\0';

  /* Clamp datasize to per-slot payload capacity to guard against a
   * corrupt or truncated ring file. */
  maxpayload = (param.pktsize > sizeof (RingPacket))
                   ? param.pktsize - (uint32_t)sizeof (RingPacket)
                   : 0;
  if (packet->datasize > maxpayload)
  {
    lprintf (0, "%s(): clamping corrupt datasize %" PRIu32 " > max %" PRIu32 " at offset %" PRId64,
             __func__, packet->datasize, maxpayload, offset);
    packet->datasize = maxpayload;
  }

  /* Copy packet data if a pointer is supplied */
  if (packetdata)
    memcpy (packetdata, (uint8_t *)pkt + sizeof (RingPacket), packet->datasize);

  /* Sanity check that the data was not modified during the copy */
  atomic_thread_fence (memory_order_acquire);
  if (pkttime != LoadPktTime (pkt))
  {
    return RINGID_NONE;
  }

  return packet->pktid;
} /* End of RingRead() */

/***************************************************************************
 * RingRead:
 *
 * Read a requested packet ID from the ring.
 *
 * For this routine an explicit packet ID is requested and returned if
 * found.  The packet stream ID matching and rejection patterns are not
 * relevant.
 *
 * The packet pointer must point to already allocated memory.  The packet
 * data will only be returned if the packetdata pointer is not NULL and
 * points to already allocated memory.
 *
 * Returns the packet ID on success, RINGID_NONE when the packet was not
 * found and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingRead (RingReader *reader, uint64_t reqid,
          RingPacket *packet, char *packetdata)
{
  nstime_t pkttime;
  int64_t offset = -1;
  uint64_t pktid;

  if (!reader || !packet)
    return RINGID_ERROR;

  if (reqid > RINGID_MAXIMUM)
  {
    lprintf (0, "%s(): unsupported position value: %" PRIu64, __func__, reqid);
    return RINGID_ERROR;
  }

  /* Find the offset to the packet */
  if ((offset = FindOffsetForID (reqid, &pkttime)) < 0)
  {
    return RINGID_NONE;
  }

  pktid = RingReadPacket (offset, packet, packetdata);

  if (pktid == RINGID_ERROR || pktid == RINGID_NONE)
  {
    return pktid;
  }

  /* Confirm the copied slot still holds the requested ID */
  if (packet->pktid != reqid)
  {
    return RINGID_NONE;
  }

  /* Update reader position value */
  reader->pktoffset = packet->offset;
  reader->pktid     = packet->pktid;
  reader->pkttime   = packet->pkttime;

  return reqid;
} /* End of RingRead() */

/***************************************************************************
 * RingReadNext:
 *
 * Determine and read the next packet from the ring.  The packet
 * pointer must point to already allocated memory.  The packet data (payload)
 * will be returned if the packetdata pointer is not NULL.
 *
 * If the packet being searched for does not exist and is not the next
 * expected packet that will enter the ring, assume that the read
 * position has fallen off the trailing edge of the ring and
 * reposition the search at the earliest packet.
 *
 * Returns packet ID on success, RINGID_NONE when no next packet
 * and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingReadNext (RingReader *reader, RingPacket *packet, char *packetdata)
{
  RingPacket latestpkt;
  RingPacket *pkt;
  nstime_t pkttime;
  int64_t offset = -1;
  uint8_t skip;
  uint8_t atend;
  uint32_t skipped;
  uint64_t latestrv;

  int64_t earliestoffset;
  int64_t latestoffset;
  int64_t eoboffset;
  const int64_t maxoffset   = param.maxoffset;
  const uint32_t pktsize    = config.pktsize;
  pcre2_match_context *mctx = GetMatchContext ();

  if (!reader || !packet)
    return RINGID_ERROR;

  earliestoffset = param.earliestoffset;
  latestoffset   = param.latestoffset;

  /* If ring is empty return immediately */
  if (latestoffset < 0)
  {
    /* For readers already streaming data, position them to the eventual earliest */
    if (reader->pktoffset < 0 && (reader->pktid == RINGID_NEXT || reader->pktid == RINGID_NONE))
    {
      reader->pktid = RINGID_EARLIEST;
    }

    return RINGID_NONE;
  }

  /* Determine the end-of-buffer offset as the one following the latest offset */
  eoboffset = NEXTOFFSET (latestoffset, maxoffset, pktsize);

  /* For a reader already streaming (caught up or not), determine the next
   * offset up front so a caught-up reader can return immediately without
   * paying for a read of the latest packet below */
  if (reader->pktoffset >= 0)
  {
    offset = NEXTOFFSET (reader->pktoffset, maxoffset, pktsize);

    if (offset == eoboffset)
      return RINGID_NONE;
  }

  /* Read the latest packet, needed both for initial positioning below and to
   * bound the reposition-detection scan that follows */
  latestrv = RingReadPacket (latestoffset, &latestpkt, NULL);

  if (latestrv == RINGID_NONE || latestrv == RINGID_ERROR)
    return RINGID_NONE;

  /* Determine offset for initial read or relative positions */
  if (reader->pktoffset < 0)
  {
    if (reader->pktid == RINGID_NEXT || reader->pktid == RINGID_NONE)
    {
      /* Position reader at the latest packet */
      reader->pktoffset = latestpkt.offset;
      reader->pktid     = latestpkt.pktid;
      reader->pkttime   = latestpkt.pkttime;

      /* There is no next packet so return */
      return RINGID_NONE;
    }
    else if (reader->pktid == RINGID_LATEST)
    {
      offset = latestoffset;
    }
    else if (reader->pktid == RINGID_EARLIEST)
    {
      offset = earliestoffset;
    }
    else if (reader->pktid <= RINGID_MAXIMUM)
    {
      /* Positioned before a specific packet, find it for inclusive delivery */
      if ((offset = FindOffsetForID (reader->pktid, NULL)) < 0)
      {
        /* Not yet in the ring: position at the latest packet and wait */
        if (reader->pktid > latestpkt.pktid)
        {
          reader->pktoffset = latestpkt.offset;
          reader->pktid     = latestpkt.pktid;
          reader->pkttime   = latestpkt.pkttime;

          return RINGID_NONE;
        }

        /* Otherwise off the trailing edge: deliver from the earliest packet */
        offset = earliestoffset;
      }
    }
    else
    {
      lprintf (0, "%s(): unsupported packet ID value: %" PRIu64, __func__, reader->pktid);
      return RINGID_ERROR;
    }
  }

  /* Loop until we have a matching packet or advanced past the latest.
   * The end-of-buffer offset is not checked before reading a slot: in a
   * wrapped ring the earliest packet occupies that same offset. */
  skip    = 1;
  skipped = 0;
  atend   = 0;
  while (skip && !atend)
  {
    skip = 0;

    pkt = PACKETPTR (offset);

    /* Sample pkttime, then re-check below (after the copy) to detect a
     * concurrent RingWrite() overwriting this slot */
    pkttime = LoadPktTime (pkt);
    atomic_thread_fence (memory_order_acquire);

    /* Determine if this is a valid packet by checking that the packet time has
     * not advanced past the lastest time */
    if (pkttime == NSTUNSET || pkttime > latestpkt.pkttime)
    {
      /* If the packet is mid-write (NSTUNSET) or has been replaced, assume the
       * reader has been lapped (fallen off the trailing edge of the buffer)
       * and reposition to the earliest packet */

      offset = param.earliestoffset;
      skipped++;

      /* Safety value to avoid skipping off the trailing edge of the buffer forever */
      if (skipped >= 100)
      {
        lprintf (0, "%s(): skipped off trailing edge of buffer %d times", __func__, skipped);
        return RINGID_NONE;
      }

      skip = 1;
      continue;
    }

    skipped = 0;

    /* Update reader position, using the sampled pkttime validated below */
    reader->pktoffset = offset;
    reader->pktid     = pkt->pktid;
    reader->pkttime   = pkttime;

    /* Bound streamid length to slot size */
    PCRE2_SIZE sidlen = strnlen (pkt->streamid, MAXSTREAMID);

    /* Test allowed expression if available, skip if NOT matched */
    if (reader->allowed)
      if (pcre2_match (reader->allowed, (PCRE2_SPTR8)pkt->streamid, sidlen, 0, 0,
                       reader->allowed_data, mctx) < 0)
        skip = 1;

    /* Test forbidden expression if available, skip if matched */
    if (reader->forbidden && skip == 0)
      if (pcre2_match (reader->forbidden, (PCRE2_SPTR8)pkt->streamid, sidlen, 0, 0,
                       reader->forbidden_data, mctx) >= 0)
        skip = 1;

    /* Test match expression if available, skip if NOT matched */
    if (reader->match && skip == 0)
      if (pcre2_match (reader->match, (PCRE2_SPTR8)pkt->streamid, sidlen, 0, 0,
                       reader->match_data, mctx) < 0)
        skip = 1;

    /* Test reject expression if available, skip if matched */
    if (reader->reject && skip == 0)
      if (pcre2_match (reader->reject, (PCRE2_SPTR8)pkt->streamid, sidlen, 0, 0,
                       reader->reject_data, mctx) >= 0)
        skip = 1;

    /* If skipping this packet determine the next packet in the ring */
    if (skip)
    {
      offset = NEXTOFFSET (offset, maxoffset, pktsize);

      if (offset == eoboffset)
        atend = 1;
    }
  }

  if (atend)
  {
    return RINGID_NONE;
  }

  /* Copy packet header */
  memcpy (packet, pkt, sizeof (RingPacket));
  packet->streamid[MAXSTREAMID - 1] = '\0';

  /* Clamp datasize to per-slot payload capacity to guard against a
   * corrupt or truncated ring file. */
  {
    uint32_t maxpayload = (param.pktsize > sizeof (RingPacket))
                              ? param.pktsize - (uint32_t)sizeof (RingPacket)
                              : 0;
    if (packet->datasize > maxpayload)
    {
      lprintf (0, "%s(): clamping corrupt datasize %" PRIu32 " > max %" PRIu32 " at offset %" PRId64,
               __func__, packet->datasize, maxpayload, offset);
      packet->datasize = maxpayload;
    }
  }

  /* Copy packet data if a pointer is supplied */
  if (packetdata)
    memcpy (packetdata, (uint8_t *)pkt + sizeof (RingPacket), packet->datasize);

  /* Sanity check that the data was not overwritten during processing */
  atomic_thread_fence (memory_order_acquire);
  if (pkttime != LoadPktTime (pkt))
  {
    return RINGID_NONE;
  }

  return packet->pktid;
} /* End of RingReadNext() */

/***************************************************************************
 * RingPosition:
 *
 * Set the ring reading position to the specified packet ID, checking
 * that the ID is a valid packet in the ring.  If the pkttime value is
 * not NSTUNSET it will also be checked and should match the requested
 * packet ID.  The current read position is not changed if any errors
 * occur.
 *
 * If the packet is successfully found the RingReader.pktid will be
 * updated.
 *
 * Returns packet ID on success, RINGID_NONE when the packet was not
 * found and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingPosition (RingReader *reader, uint64_t pktid, nstime_t pkttime)
{
  RingPacket lookup;
  RingPacket *pkt;
  nstime_t ptime;
  int64_t offset;

  if (!reader)
    return RINGID_ERROR;

  if (param.latestoffset < 0)
    return RINGID_NONE;

  /* Determine packet ID for relative positions */
  if (pktid == RINGID_EARLIEST)
  {
    pktid = RingReadPacket (param.earliestoffset, &lookup, NULL);
  }
  else if (pktid == RINGID_LATEST)
  {
    pktid = RingReadPacket (param.latestoffset, &lookup, NULL);
  }

  if (pktid > RINGID_MAXIMUM)
  {
    lprintf (0, "%s(): unsupported position value: %" PRIu64, __func__, pktid);
    return RINGID_ERROR;
  }

  /* Find the offset to the packet */
  if ((offset = FindOffsetForID (pktid, &ptime)) < 0)
  {
    return RINGID_NONE;
  }

  pkt = PACKETPTR (offset);

  /* Check for matching pkttime if not NSTUNSET or NSTERROR */
  if (pkttime != NSTUNSET && pkttime != NSTERROR)
  {
    if (pkttime != ptime)
    {
      return RINGID_NONE;
    }
  }

  /* Sanity check that the data was not overwritten during the copy */
  if (pktid != pkt->pktid)
  {
    return RINGID_NONE;
  }

  /* Update reader position value */
  reader->pktoffset = offset;
  reader->pktid     = pktid;
  reader->pkttime   = ptime;

  return pktid;
} /* End of RingPosition() */

/***************************************************************************
 * RingPositionBefore:
 *
 * Set the ring reading position to just before the specified packet
 * ID such that a subsequent RingReadNext() will return that packet,
 * or the first following match if it is no longer present.  The
 * RINGID_EARLIEST and RINGID_LATEST values are supported and remain
 * relative until the next read, including for an empty ring.
 *
 * Returns the ID of the packet expected to be read first if it can
 * be determined, RINGID_NONE otherwise, and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingPositionBefore (RingReader *reader, uint64_t pktid)
{
  RingPacket lookup;
  uint64_t resolved = RINGID_NONE;

  if (!reader)
    return RINGID_ERROR;

  if (pktid > RINGID_MAXIMUM && pktid != RINGID_EARLIEST && pktid != RINGID_LATEST)
  {
    lprintf (0, "%s(): unsupported position value: %" PRIu64, __func__, pktid);
    return RINGID_ERROR;
  }

  /* Resolve the ID expected to be read first when possible */
  if (param.latestoffset >= 0)
  {
    if (pktid == RINGID_EARLIEST)
      resolved = RingReadPacket (param.earliestoffset, &lookup, NULL);
    else if (pktid == RINGID_LATEST)
      resolved = RingReadPacket (param.latestoffset, &lookup, NULL);
    else if (FindOffsetForID (pktid, NULL) >= 0)
      resolved = pktid;
  }

  /* Update reader position, resolved to a packet on the next read */
  reader->pktoffset = -1;
  reader->pktid     = pktid;
  reader->pkttime   = NSTUNSET;

  return (resolved <= RINGID_MAXIMUM) ? resolved : RINGID_NONE;
} /* End of RingPositionBefore() */

/***************************************************************************
 * RingAfter:
 *
 * Set the ring reading position to a matching packet (as defined by
 * the readers's match and reject expressions) based on packet data
 * time.  The ring is searched from the earliest packet forward,
 * stopping at the first matching packet with a data end time after
 * the reference time.
 *
 * The position can be set either at or just before the matched packet
 * depending on the whence argument.
 *
 * whence:
 * 0 = Set position just before the matched packet, such that a
 *     subsequent RingReadNext() returns the matched packet.
 * 1 = Set position at the matched packet, such that a subsequent
 *     RingReadNext() returns the following packet.
 *
 * If a packet is successfully found in the ring the reader.pktid will
 * be updated.  The current read position is not changed if any errors
 * occur.
 *
 * Returns packet ID on success, RINGID_NONE when the packet was not
 * found and RINGID_ERROR on error.
 ***************************************************************************/
uint64_t
RingAfter (RingReader *reader, nstime_t reftime, int whence)
{
  RingPacket *pkt1 = NULL;
  uint64_t pktid;
  nstime_t pkttime;
  int64_t offset;
  uint64_t skipped = 0;
  uint8_t found    = 0;
  uint8_t skip;
  const int64_t maxoffset   = param.maxoffset;
  const uint32_t pktsize    = config.pktsize;
  pcre2_match_context *mctx = GetMatchContext ();

  if (!reader)
    return RINGID_ERROR;

  /* Nothing to search if the ring is empty */
  if (param.earliestoffset < 0 || param.latestoffset < 0)
    return RINGID_NONE;

  /* Start searching with the earliest packet in the ring */
  offset = param.earliestoffset;

  /* Loop through packets in forward order */
  while (skipped < param.maxpackets)
  {
    skip = 0;

    /* Get pointer to RingPacket */
    pkt1 = PACKETPTR (offset);

    /* Test if packet is earlier than reference time, this will avoid the
     * regex tests for packets that we will eventually skip anyway */
    if (pkt1->dataend < reftime)
      skip = 1;

    /* Only bother with the regex tests, including the streamid length
     * bound, if the packet has not already been skipped above */
    if (!skip)
    {
      /* Bound streamid length to slot size, in-ring streamid may not be NUL-terminated */
      PCRE2_SIZE sidlen = strnlen (pkt1->streamid, MAXSTREAMID);

      /* Test allowed expression if available, skip if NOT matched */
      if (reader->allowed && !skip)
        if (pcre2_match (reader->allowed, (PCRE2_SPTR8)pkt1->streamid, sidlen, 0, 0,
                         reader->allowed_data, mctx) < 0)
          skip = 1;

      /* Test forbidden expression if available, skip if matched */
      if (reader->forbidden && !skip)
        if (pcre2_match (reader->forbidden, (PCRE2_SPTR8)pkt1->streamid, sidlen, 0, 0,
                         reader->forbidden_data, mctx) >= 0)
          skip = 1;

      /* Test match expression if available, skip if NOT matched */
      if (reader->match && !skip)
        if (pcre2_match (reader->match, (PCRE2_SPTR8)pkt1->streamid, sidlen, 0, 0,
                         reader->match_data, mctx) < 0)
          skip = 1;

      /* Test reject expression if available, skip if matched */
      if (reader->reject && !skip)
        if (pcre2_match (reader->reject, (PCRE2_SPTR8)pkt1->streamid, sidlen, 0, 0,
                         reader->reject_data, mctx) >= 0)
          skip = 1;
    }

    /* Done if this matching packet has a data end time after that specified */
    if (!skip && pkt1->dataend > reftime)
    {
      found = 1;
      break;
    }

    /* Done if we reach the latest packet */
    if (offset == param.latestoffset)
    {
      break;
    }

    offset = NEXTOFFSET (offset, maxoffset, pktsize);
    skipped++;
  }

  /* No matching packet was found in the ring */
  if (!found)
  {
    return RINGID_NONE;
  }

  /* Sample pkttime, then read the remaining fields, then re-check pkttime
   * to detect the slot being overwritten while it was read */
  pkttime = LoadPktTime (pkt1);
  atomic_thread_fence (memory_order_acquire);

  offset = pkt1->offset;
  pktid  = pkt1->pktid;

  atomic_thread_fence (memory_order_acquire);
  if (pkttime == NSTUNSET || pkttime != LoadPktTime (pkt1))
  {
    return RINGID_NONE;
  }

  /* Update reader position, either just before the matched packet so the
   * next read returns it, or at the matched packet */
  if (whence == 0)
  {
    reader->pktoffset = -1;
    reader->pktid     = pktid;
    reader->pkttime   = NSTUNSET;
  }
  else
  {
    reader->pktoffset = offset;
    reader->pktid     = pktid;
    reader->pkttime   = pkttime;
  }

  return pktid;
} /* End of RingAfter() */

/***************************************************************************
 * RingAfterRev:
 *
 * Set the ring reading position to a matching packet (as defined by
 * the readers's match and reject expressions) based on packet data
 * time.  The ring is searched from the latest packet backward,
 * stopping at the first matching packet with a data end time after
 * the reference time or after skipping pktlimit number of packets.
 *
 * The position can be set either at or just before the matched packet
 * depending on the whence argument.
 *
 * whence:
 * 0 = Set position just before the matched packet, such that a
 *     subsequent RingReadNext() returns the matched packet.
 * 1 = Set position at the matched packet, such that a subsequent
 *     RingReadNext() returns the following packet.
 *
 * If a packet is successfully found in the ring the reader.pktid will
 * be updated.  The current read position is not changed if any errors
 * occur.
 *
 * Returns packet ID on success, RINGID_NONE when the packet was not
 * found and -1 on error.
 ***************************************************************************/
uint64_t
RingAfterRev (RingReader *reader, nstime_t reftime, uint64_t pktlimit,
              int whence)
{
  RingPacket *pkt  = NULL;
  RingPacket *spkt = NULL;
  nstime_t pkttime = NSTUNSET;
  uint64_t pktid   = RINGID_NONE;
  int64_t offset;
  int64_t soffset;
  uint64_t count = 0;
  uint8_t skip;
  const int64_t maxoffset   = param.maxoffset;
  const uint32_t pktsize    = config.pktsize;
  pcre2_match_context *mctx = GetMatchContext ();

  if (!reader)
    return RINGID_ERROR;

  /* Nothing to search if the ring is empty */
  if (param.earliestoffset < 0 || param.latestoffset < 0)
    return RINGID_NONE;

  /* Start searching with the latest packet in the ring */
  offset  = param.latestoffset;
  soffset = offset;

  /* Loop through packets in reverse order */
  while (count < pktlimit)
  {
    skip = 0;

    /* Get pointer to RingPacket */
    spkt = PACKETPTR (soffset);

    /* Bound streamid length to slot size, in-ring streamid may not be NUL-terminated */
    PCRE2_SIZE sidlen = strnlen (spkt->streamid, MAXSTREAMID);

    /* Test allowed expression if available, skip if NOT matched */
    if (reader->allowed)
      if (pcre2_match (reader->allowed, (PCRE2_SPTR8)spkt->streamid, sidlen, 0, 0,
                       reader->allowed_data, mctx) < 0)
        skip = 1;

    /* Test forbidden expression if available, skip if matched */
    if (reader->forbidden && !skip)
      if (pcre2_match (reader->forbidden, (PCRE2_SPTR8)spkt->streamid, sidlen, 0, 0,
                       reader->forbidden_data, mctx) >= 0)
        skip = 1;

    /* Test match expression if available, skip if NOT matched */
    if (reader->match && !skip)
      if (pcre2_match (reader->match, (PCRE2_SPTR8)spkt->streamid, sidlen, 0, 0,
                       reader->match_data, mctx) < 0)
        skip = 1;

    /* Test reject expression if available, skip if matched */
    if (reader->reject && !skip)
      if (pcre2_match (reader->reject, (PCRE2_SPTR8)spkt->streamid, sidlen, 0, 0,
                       reader->reject_data, mctx) >= 0)
        skip = 1;

    if (!skip)
    {
      /* Set ID and time if this matching packet has a data end time after that specified */
      if (spkt->dataend > reftime)
      {
        /* Sample pkttime before the remaining fields, re-checked below */
        pkttime = LoadPktTime (spkt);
        atomic_thread_fence (memory_order_acquire);
        offset = soffset;
        pktid  = spkt->pktid;
        pkt    = spkt;
      }

      /* Done if we reach a matching packet with earlier start time */
      if (spkt->datastart < reftime)
      {
        break;
      }
    }

    /* Done if we reach the earliest packet */
    if (soffset == param.earliestoffset)
    {
      break;
    }

    soffset = PREVOFFSET (soffset, maxoffset, pktsize);
    count++;
  }

  /* Safety valve, if no packets were ever seen */
  if (!pkt)
  {
    return RINGID_NONE;
  }

  /* Sanity check that the data was not overwritten while it was read */
  atomic_thread_fence (memory_order_acquire);
  if (pkttime == NSTUNSET || pkttime != LoadPktTime (pkt))
  {
    return RINGID_NONE;
  }

  /* Update reader position, either just before the matched packet so the
   * next read returns it, or at the matched packet */
  if (whence == 0)
  {
    reader->pktoffset = -1;
    reader->pktid     = pktid;
    reader->pkttime   = NSTUNSET;
  }
  else
  {
    reader->pktoffset = offset;
    reader->pktid     = pktid;
    reader->pkttime   = pkttime;
  }

  return pktid;
} /* End of RingAfterRev() */

/***************************************************************************
 * UpdatePattern:
 *
 * Compile the supplied regex pattern (and data) and assign to the
 * provided pointers.
 *
 * The description is used in error messages to describe the pattern.
 *
 * Returns 0 on success and -1 on error.
 ***************************************************************************/
int
UpdatePattern (pcre2_code **code, pcre2_match_data **data,
               const char *pattern, const char *description)
{
  int errcode;
  PCRE2_SIZE erroffset;
  PCRE2_UCHAR buffer[256];

  if (!code || !data)
    return -1;

  /* Compile pattern and assign to reader */
  if (pattern)
  {
    /* Free existing compiled expression */
    if (*code)
      pcre2_code_free (*code);
    if (*data)
      pcre2_match_data_free (*data);

    *data = NULL;

    /* Compile regex */
    *code = pcre2_compile ((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                           PCRE2_COMPILE_OPTIONS, &errcode, &erroffset, NULL);

    if (*code == NULL)
    {
      pcre2_get_error_message (errcode, buffer, sizeof (buffer));
      lprintf (0, "%s(): Error compiling %s expression at %zu: %s",
               __func__, (description ? description : ""),
               erroffset, buffer);
      return -1;
    }

    /* Enable PCRE2 JIT compilation */
    int jit_rc = pcre2_jit_compile (*code, PCRE2_JIT_COMPLETE);

    /* Accept success or unsupported patterns, but fail on other errors */
    if (!(jit_rc == 0 || jit_rc == PCRE2_ERROR_JIT_UNSUPPORTED))
    {
      lprintf (0, "%s(): Error enabling PCRE2 JIT compilation", __func__);
      pcre2_code_free (*code);
      *code = NULL;
      *data = NULL;
      return -1;
    }

    *data = pcre2_match_data_create_from_pattern (*code, NULL);

    if (*data == NULL)
    {
      lprintf (0, "%s(): Error allocating match data for %s expression",
               __func__, (description ? description : ""));
      pcre2_code_free (*code);
      *code = NULL;
      return -1;
    }
  }
  /* If no pattern, clear any existing regex */
  else
  {
    if (*code)
      pcre2_code_free (*code);
    *code = NULL;

    if (*data)
      pcre2_match_data_free (*data);
    *data = NULL;
  }

  return 0;
} /* End of UpdatePattern() */

/***************************************************************************
 * GetMatchContext:
 *
 * Return a process-wide pcre2_match_context with conservative resource
 * limits to prevent ReDoS from client-supplied regex patterns.  The
 * context is initialised exactly once via pthread_once and is never freed
 * (safe for process-lifetime use).
 *
 * Limits chosen:
 *   match_limit  100000  – bounds interpreted backtrack steps per string
 *   depth_limit  1000    – bounds recursion depth (catastrophic patterns)
 *   heap_limit   1024    – KiB of JIT heap per match
 *
 * Returns the shared context pointer (never NULL after first call).
 ***************************************************************************/
static pcre2_match_context *global_match_context = NULL;
static pthread_once_t match_context_once         = PTHREAD_ONCE_INIT;

static void
InitMatchContext (void)
{
  global_match_context = pcre2_match_context_create (NULL);

  /* The ReDoS mitigations (match/depth/heap limits) are applied to this
   * shared context; pcre2_match() tolerates a NULL context but silently
   * disables those limits, which is unacceptable since client-supplied
   * regexes could then cause unbounded CPU/memory usage.  Treat the
   * allocation failure as fatal instead of starting in a degraded mode. */
  if (!global_match_context)
  {
    lprintf (0, "FATAL: %s(): pcre2_match_context_create() failed; "
                "cannot enforce regex resource limits, aborting startup",
             __func__);
    exit (1);
  }

  pcre2_set_match_limit (global_match_context, 100000);
  pcre2_set_depth_limit (global_match_context, 1000);
  pcre2_set_heap_limit (global_match_context, 1024);
} /* End of InitMatchContext() */

pcre2_match_context *
GetMatchContext (void)
{
  pthread_once (&match_context_once, InitMatchContext);
  return global_match_context;
} /* End of GetMatchContext() */

/***************************************************************************
 * StreamIDCmp:
 *
 * Compare the stream IDs of two RingStream entries, for use with
 * qsort() to sort an array of RingStream entries by stream ID.
 *
 * Return the result of strncmp() on the stream IDs.
 ***************************************************************************/
static int
StreamIDCmp (const void *a, const void *b)
{
  return strncmp (((const RingStream *)a)->streamid,
                  ((const RingStream *)b)->streamid,
                  MAXSTREAMID);
} /* End of StreamIDCmp() */

/***************************************************************************
 * RingStreamAllowed:
 *
 * Test a stream ID against a reader's allowed and forbidden
 * expressions.
 *
 * If reader is NULL the stream ID is always allowed.
 *
 * Return 1 if the stream ID is allowed and 0 if not.
 ***************************************************************************/
int
RingStreamAllowed (RingReader *reader, const char *streamid)
{
  PCRE2_SIZE sidlen;
  pcre2_match_context *mctx;

  if (!reader)
    return 1;

  /* Bound streamid length to slot size, in-ring streamid may not be NUL-terminated */
  sidlen = strnlen (streamid, MAXSTREAMID);
  mctx   = GetMatchContext ();

  /* Test allowed expression if available, reject if NOT matched */
  if (reader->allowed)
    if (pcre2_match (reader->allowed, (PCRE2_SPTR8)streamid, sidlen, 0, 0,
                     reader->allowed_data, mctx) < 0)
      return 0;

  /* Test forbidden expression if available, reject if matched */
  if (reader->forbidden)
    if (pcre2_match (reader->forbidden, (PCRE2_SPTR8)streamid, sidlen, 0, 0,
                     reader->forbidden_data, mctx) >= 0)
      return 0;

  return 1;
} /* End of RingStreamAllowed() */

/***************************************************************************
 * StreamIDSelected:
 *
 * Test a stream ID against a reader's allowed, forbidden, match and
 * reject expressions.
 *
 * If reader is NULL the stream ID is always selected.
 *
 * Return 1 if the stream ID is selected and 0 if it is filtered out.
 ***************************************************************************/
static int
StreamIDSelected (RingReader *reader, const char *streamid)
{
  PCRE2_SIZE sidlen;
  pcre2_match_context *mctx;

  if (!reader)
    return 1;

  if (!RingStreamAllowed (reader, streamid))
    return 0;

  /* Bound streamid length to slot size, in-ring streamid may not be NUL-terminated */
  sidlen = strnlen (streamid, MAXSTREAMID);
  mctx   = GetMatchContext ();

  /* Test match expression if available, reject if NOT matched */
  if (reader->match)
    if (pcre2_match (reader->match, (PCRE2_SPTR8)streamid, sidlen, 0, 0,
                     reader->match_data, mctx) < 0)
      return 0;

  /* Test reject expression if available, reject if matched */
  if (reader->reject)
    if (pcre2_match (reader->reject, (PCRE2_SPTR8)streamid, sidlen, 0, 0,
                     reader->reject_data, mctx) >= 0)
      return 0;

  return 1;
} /* End of StreamIDSelected() */

/***************************************************************************
 * SnapshotStreams:
 *
 * Recursively walk the stream index in stream-key order, appending a
 * memcpy() of each RingStream entry to array, stopping once capacity
 * entries have been written.  Caller must hold param.streamlock.
 ***************************************************************************/
static void
SnapshotStreams (RBTree *tree, RBNode *node, RingStream *array,
                 uint32_t *count, uint32_t capacity)
{
  if (node == tree->nil || *count >= capacity)
    return;

  SnapshotStreams (tree, node->left, array, count, capacity);

  if (*count < capacity)
    memcpy (&array[(*count)++], node->data, sizeof (RingStream));

  SnapshotStreams (tree, node->right, array, count, capacity);
} /* End of SnapshotStreams() */

/***************************************************************************
 * GetStreams:
 *
 * Build a copy of the stream index as an array sorted on stream ID.
 * It is up to the caller to free the array with free().
 *
 * If reader is not NULL only the streamids that match the reader's
 * allowed and match expressions and do not match the reader's
 * forbidden and reject expressions will be included in the output.
 *
 * On success *streams is set to an allocated array of *count entries,
 * or NULL if *count is 0.
 *
 * Return 0 on success and -1 on error.
 ***************************************************************************/
int
GetStreams (RingReader *reader, RingStream **streams, uint32_t *count)
{
  RingStream *snapshot    = NULL;
  uint32_t snapshot_count = 0;
  uint32_t filled         = 0;
  uint32_t kept           = 0;

  if (!streams || !count)
    return -1;

  *streams = NULL;
  *count   = 0;

  /* Hold streamlock only long enough to copy the tree into a contiguous
   * array, exactly sized using streamcount (mutated only under this same
   * lock).  PCRE2 filtering and sorting run after the lock is released,
   * so they never delay packet writers waiting on streamlock. */
  pthread_mutex_lock (&param.streamlock);

  snapshot_count = param.streamcount;

  if (snapshot_count > 0)
  {
    snapshot = (RingStream *)malloc ((size_t)snapshot_count * sizeof (RingStream));
    if (snapshot == NULL)
    {
      lprintf (0, "%s(): Error allocating snapshot", __func__);
      pthread_mutex_unlock (&param.streamlock);
      return -1;
    }

    SnapshotStreams (param.streamidx, param.streamidx->root->left, snapshot, &filled, snapshot_count);
  }

  pthread_mutex_unlock (&param.streamlock);

  /* Lock released.  Now run the (potentially expensive) PCRE2 filters,
   * compacting surviving entries in place.  Bound by filled, not
   * snapshot_count: if the tree walk wrote fewer entries than the count
   * suggested, the remainder of the array was never initialized. */
  for (uint32_t i = 0; i < filled; i++)
  {
    if (!StreamIDSelected (reader, snapshot[i].streamid))
      continue;

    if (kept != i)
      snapshot[kept] = snapshot[i];
    kept++;
  }

  if (kept == 0)
  {
    free (snapshot);
    return 0;
  }

  /* Shrink to the retained count; keep the larger block on failure */
  if (kept != snapshot_count)
  {
    RingStream *shrunk = (RingStream *)realloc (snapshot, kept * sizeof (RingStream));
    if (shrunk != NULL)
      snapshot = shrunk;
  }

  /* Sort array on the stream IDs if more than one entry */
  if (kept > 1)
    qsort (snapshot, kept, sizeof (RingStream), StreamIDCmp);

  *streams = snapshot;
  *count   = kept;

  return 0;
} /* End of GetStreams() */

/***************************************************************************
 * CountStreams:
 *
 * Count the streams in the stream index selected by a reader's allowed,
 * forbidden, match and reject expressions.
 *
 * If reader is NULL, or has no filter expressions compiled, this is an
 * O(1) read of the (atomic) stream count.  Otherwise it counts entries
 * returned by GetStreams().
 *
 * Return 0 on success and -1 on error.
 ***************************************************************************/
int
CountStreams (RingReader *reader, uint32_t *count)
{
  RingStream *streams = NULL;

  if (!count)
    return -1;

  *count = 0;

  /* Fast path: no filters means every indexed stream is selected */
  if (!reader ||
      (!reader->allowed && !reader->forbidden && !reader->match && !reader->reject))
  {
    *count = param.streamcount;
    return 0;
  }

  if (GetStreams (reader, &streams, count))
    return -1;

  free (streams);

  return 0;
} /* End of CountStreams() */

/***************************************************************************
 * FindOffsetForID:
 *
 * Determine the offset in the ring buffer to a specified packet ID.
 *
 * Assumptions:
 *
 * - If the earliest ID >= largest ID, they represent a range between
 * which the pktid must fall and they increase from earliest to latest.
 *
 * - If the earliest ID < largest ID, the ID set has no useful ordering.
 *
 * If pkttime is not NULL, it will be set to the time of the packet if the
 * search is successful.
 *
 * Return the offset to the RingPacket on success or -1 if no match.
 ***************************************************************************/
static inline int64_t
FindOffsetForID (uint64_t pktid, nstime_t *pkttime)
{
  RingPacket *packet = NULL;
  RingPacket *earliestpkt;
  RingPacket *latestpkt;
  int64_t earliestoffset;
  uint64_t earliestid;
  nstime_t earliesttime;
  int64_t latestoffset;
  uint64_t latestid;
  nstime_t latesttime;
  int64_t offset;

  earliestoffset = param.earliestoffset;
  latestoffset   = param.latestoffset;

  /* Ring is empty */
  if (earliestoffset < 0 || latestoffset < 0)
  {
    return -1;
  }

  /* Read the earliest and latest packet IDs directly from the ring,
   * validating each with a pkttime sample/re-check instead of paying for
   * two full RingReadPacket() struct copies */
  earliestpkt  = PACKETPTR (earliestoffset);
  earliesttime = LoadPktTime (earliestpkt);
  atomic_thread_fence (memory_order_acquire);
  earliestid = earliestpkt->pktid;
  atomic_thread_fence (memory_order_acquire);
  if (earliesttime == NSTUNSET || earliesttime != LoadPktTime (earliestpkt))
    return -1;

  latestpkt  = PACKETPTR (latestoffset);
  latesttime = LoadPktTime (latestpkt);
  atomic_thread_fence (memory_order_acquire);
  latestid = latestpkt->pktid;
  atomic_thread_fence (memory_order_acquire);
  if (latesttime == NSTUNSET || latesttime != LoadPktTime (latestpkt))
    return -1;

  /* Earliest ID is less than latest ID.
   * Assume they increment from earliest to latest.
   * Assume the pktid must exist within the range. */
  if (earliestid <= latestid)
  {
    /* Check that requested packet ID is within earliest - latest range */
    if (pktid < earliestid || pktid > latestid)
    {
      return -1;
    }

    int64_t ringmod                = param.maxoffset + config.pktsize;
    int64_t latestoffset_unwrapped = (latestoffset < earliestoffset) ? latestoffset + ringmod : latestoffset;

    int64_t lowpkt  = 0;
    int64_t highpkt = (latestoffset_unwrapped - earliestoffset) / param.pktsize;
    int64_t midpkt;

    /* Binary search for a matching ID */
    while (lowpkt <= highpkt)
    {
      midpkt = lowpkt + (highpkt - lowpkt) / 2;

      int64_t offset_unwrapped = earliestoffset + (midpkt * param.pktsize);

      offset = (offset_unwrapped >= ringmod) ? offset_unwrapped - ringmod : offset_unwrapped;

      packet = PACKETPTR (offset);

      /* If packet ID is found return the offset */
      if (packet->pktid == pktid)
      {
        if (pkttime)
          *pkttime = packet->pkttime;

        return offset;
      }

      if (packet->pktid < pktid)
      {
        lowpkt = midpkt + 1;
      }
      else
      {
        highpkt = midpkt - 1;
      }
    }
  }
  /* Otherwise the ID set has either wrapped or is otherwise unordered */
  else
  {
    /* Brute force search backwards from the latest */
    offset = NEXTOFFSET (latestoffset, param.maxoffset, param.pktsize);
    do
    {
      offset = PREVOFFSET (offset, param.maxoffset, param.pktsize);

      packet = PACKETPTR (offset);

      if (packet->pktid == pktid)
      {
        if (pkttime)
          *pkttime = packet->pkttime;

        return offset;
      }
    } while (offset != earliestoffset);
  }

  return -1;
} /* End of FindOffsetForID() */

/***************************************************************************
 * AddStreamIdx:
 *
 * Add a RingStream to the specified stream index, no checking is done
 * to determine if this entry already exists.  Return a pointer to the
 * newly generated Key if **ppkey is supplied.
 *
 * NOTE: The tree key is a 64-bit FNV-1a hash of the stream ID. In the
 * extremely unlikely event of a hash collision between two distinct stream
 * IDs, one stream's entry would silently shadow the other in the index.
 * With a 64-bit key space and realistic stream counts (hundreds to low
 * thousands) this probability is negligible, but it is a known design
 * constraint.
 *
 * Return a pointer to the added RingStream on success and 0 on error.
 ***************************************************************************/
static RingStream *
AddStreamIdx (RBTree *streamidx, RingStream *stream, Key **ppkey)
{
  Key *newkey;
  RingStream *newdata;

  if (!streamidx || !stream)
    return 0;

  /* Allocate new tree key and data node */
  newkey  = (Key *)malloc (sizeof (Key));
  newdata = (RingStream *)malloc (sizeof (RingStream));

  if (!newkey || !newdata)
  {
    free (newkey);
    free (newdata);
    return 0;
  }

  /* Populate the new data node and key */
  memcpy (newdata, stream, sizeof (RingStream));
  *newkey = FNVhash64 (newdata->streamid);

  /* Add to the stream index */
  if (!RBTreeInsert (streamidx, newkey, newdata, 0))
  {
    free (newkey);
    free (newdata);
    return 0;
  }

  /* Set pointer to hash key if requested */
  if (ppkey)
    *ppkey = newkey;

  return newdata;
} /* End of AddStreamIdx() */

/***************************************************************************
 * GetStreamIdx:
 *
 * Search the specified stream index for a given RingStream.
 *
 * Return a pointer to a RingStream if found or NULL if no match.
 ***************************************************************************/
static RingStream *
GetStreamIdx (RBTree *streamidx, char *streamid)
{
  RingStream *stream = NULL;
  RBNode *tnode;

  if (!streamidx || !streamid)
    return NULL;

  /* Generate key from streamid */
  Key key = FNVhash64 (streamid);

  /* Search for a matching key */
  if ((tnode = RBFind (streamidx, &key)))
  {
    stream = (RingStream *)tnode->data;
  }

  return stream;
} /* End of GetStreamIdx() */

/***************************************************************************
 * DelStreamIdx:
 *
 * Remove the specified stream ID from the stream index.
 *
 * Return 0 on success and -1 on error.
 ***************************************************************************/
static int
DelStreamIdx (RBTree *streamidx, char *streamid)
{
  Key key;
  RBNode *tnode;

  if (!streamidx || !streamid)
    return -1;

  /* Generate key from streamid */
  key = FNVhash64 (streamid);

  /* Search for a matching key */
  if ((tnode = RBFind (streamidx, &key)))
  {
    RBDelete (streamidx, tnode);
  }

  return (tnode) ? 0 : -1;
} /* End of DelStreamIdx() */
