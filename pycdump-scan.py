#! /usr/bin/env python3
#-
# Copyright (c) 2017 Alexandre Joannou
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import argparse
import multiprocessing
from collections import OrderedDict, defaultdict
from operator import itemgetter
import struct
import concurrent.futures as cf
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment
import os

################################
# Parse command line arguments #
################################

def auto_int (x):
    return int(x,0)

parser = argparse.ArgumentParser(description='scans a FreeBSD coredump file and return statistics on memory utilisation')

parser.add_argument('coredumps', type=str, nargs='+', metavar='COREDUMP',
                    help="COREDUMP file(s) to scan")
nb_cpu = multiprocessing.cpu_count()
parser.add_argument('-n', '--nb-processes', type=auto_int, default=nb_cpu, metavar='N',
                    help="use N processes (default: {})".format(nb_cpu))
gsizes = [4,8,16,32,64,128,256]
parser.add_argument('-s', '--group-sizes', type=auto_int, default=gsizes, nargs='+', metavar='GROUPSZ',
                    help="specify group size(s) GROUPSZ(s) (in number of 64-bit (8-Byte) words) to be considered for statistics gathering (default: {})".format(gsizes))
parser.add_argument("--dump-ptr-vector", help="Dump a file with extension .vecbin in the current working dir, which is just a boolean bit vector of whether this location contains a pointer or not.", action="store_true")

args = parser.parse_args()

########################
# Open a coredump file #
########################

def openCoreDump(filename):
    f = open(filename,"rb")
    elf = ELFFile(f)
    try:
        # assert that we can process the file
        assert elf.elfclass == 64, "elfclass == {}; only elfclass 64 is supported".format(elf.elfclass)
        assert elf.header["e_machine"] == "EM_X86_64", "e_machine == {}; only e_machine EM_X86_64 is supported".format(elf.header["e_machine"])
        assert elf.header["e_type"] == "ET_CORE", "e_type == {}; only e_type ET_CORE is supported".format(elf.header['e_type'])
        assert elf.header["e_ident"]["EI_OSABI"] == "ELFOSABI_FREEBSD", "ei_osabi == {}; only ei_osabi ELFOSABI_FREEBSD is supported".format(elf.header["e_ident"]["EI_OSABI"])
    except Exception as e:
        # in case of exception, skip to the next file
        print("Exception for {}".format(elf.stream.name))
        print(e)
        f.close()
        return None
    else:
        # get elf segments
        # check that we have a note segment
        elf.notes = None
        if isinstance(elf.get_segment(0),NoteSegment):
            elf.notes = elf.get_segment(0)
        return elf

######################################
# Scan through an individual segment #
######################################
# pickle helper
def intdd():
    return defaultdict(int)
def booldd():
    return defaultdict(bool)
def scan(idx_fname_varanges):
    idx, fname, va_ranges = idx_fname_varanges
    cdump = openCoreDump(fname)
    s = struct.Struct("<Q")
    chunks = defaultdict(intdd)
    done = defaultdict(booldd)
    prev = intdd()
    sz = 0
    ptrBitVector = []
    for b in s.iter_unpack(cdump.get_segment(idx).data()):
        # checking for zero mem
        iszero = b[0] == 0
        # checking for pointers
        isptr = False
        for low, high in va_ranges:
            if b[0] >= low and b[0] < high:
                isptr = True
                ptrBitVector.append('1')
                break
        else:
                ptrBitVector.append('0')
        # general chunks updates
        for gs in args.group_sizes:
            is_first = (sz % gs) == 0
            is_last  = (sz % gs) == gs - 1
            if is_first:
                done['zero'][gs] = False
                done['equal'][gs] = False
                prev[gs] = b[0]
                done['ptr'][gs] = False
            # updating zero and same mem chunks
            #print("A: pos {} - data = 0x{:016x} - done['zero'][{}] = {}".format(sz, b[0], gs, done['zero'][gs]))
            done['zero'][gs] |= not iszero
            done['equal'][gs] |= not(b[0] == prev[gs])
            if is_last:
                if not done['zero'][gs]:
                    chunks['zero'][gs] += 1
                if not done['equal'][gs]:
                    chunks['equal'][gs] += 1
            #print("B: pos {} - data = 0x{:016x} - done['zero'][{}] = {}".format(sz, b[0], gs, done['zero'][gs]))
            # updating ptr mem chunks
            if isptr and not done['ptr'][gs]:
                chunks['ptr'][gs] += 1
                done['ptr'][gs] = True
        # book keeping
        sz += 1
    # report
    return (idx, sz, chunks, ptrBitVector)

#############################
# FreeBSD VMMAP Note parser #
#############################

class FreeBSD_VMEntry:
    def __init__ (
            self,
            kve_structstize,
            kve_type,
            kve_start,
            kve_end,
            kve_offset,
            kve_vn_fileid,
            kve_vn_fsid,
            kve_flags,
            kve_resident,
            kve_private_resident,
            kve_protection,
            kve_ref_count,
            kve_shadow_count,
            kve_vn_type,
            kve_vn_size,
            kve_vn_rdev,
            kve_vn_mode,
            kve_status,
            _kve_spare,
            kve_path = "unknown"
            ):
        self.kve_structstize = kve_structstize
        self.kve_type = kve_type
        self.kve_start = kve_start
        self.kve_end = kve_end
        self.kve_offset = kve_offset
        self.kve_vn_fileid = kve_vn_fileid
        self.kve_vn_fsid = kve_vn_fsid
        self.kve_flags = kve_flags
        self.kve_resident = kve_resident
        self.kve_private_resident = kve_private_resident
        self.kve_protection = kve_protection
        self.kve_ref_count = kve_ref_count
        self.kve_shadow_count = kve_shadow_count
        self.kve_vn_type = kve_vn_type
        self.kve_vn_size = kve_vn_size
        self.kve_vn_rdev = kve_vn_rdev
        self.kve_vn_mode = kve_vn_mode
        self.kve_status = kve_status
        self._kve_spare = _kve_spare
        self.kve_path = kve_path
    def __str__ (self):
        #s = "structsize: {}\n".format(self.kve_structstize)
        #s += "type: {}\n".format(self.kve_type)
        #s += "kve_start: 0x{:016x}\n".format(self.kve_start)
        #s += "kve_end: 0x{:016x}\n".format(self.kve_end)
        #s += "kve_offset: {}\n".format(self.kve_offset)
        #s += "kve_vn_fileid: {}\n".format(self.kve_vn_fileid)
        #s += "kve_vn_fsid: {}\n".format(self.kve_vn_fsid)
        #s += "kve_flags: {}\n".format(self.kve_flags)
        #s += "kve_resident: {}\n".format(self.kve_resident)
        #s += "kve_private_resident: {}\n".format(self.kve_private_resident)
        #s += "kve_protection: {}\n".format(self.kve_protection)
        #s += "kve_ref_count: {}\n".format(self.kve_ref_count)
        #s += "kve_shadow_count: {}\n".format(self.kve_shadow_count)
        #s += "kve_vn_type: {}\n".format(self.kve_vn_type)
        #s += "kve_vn_size: {}\n".format(self.kve_vn_size)
        #s += "kve_vn_rdev: {}\n".format(self.kve_vn_rdev)
        #s += "kve_vn_mode: {}\n".format(self.kve_vn_mode)
        #s += "kve_status: {}\n".format(self.kve_status)
        #s += "_kve_spare: {}\n".format(self._kve_spare.decode('utf-8'))
        #s += "kve_path: {}".format(self.kve_path.decode('utf-8'))
        return "(0x{:016x} : 0x{:016x}) t: {:d}  p: {:d}  f: {:d}".format(
                self.kve_start,
                self.kve_end,
                self.kve_type,
                self.kve_protection,
                self.kve_flags)

def merge_ranges (ranges):
    merged_ranges = []
    sorted_ranges = sorted(ranges, key=itemgetter(0))
    low, high = sorted_ranges.pop(0)
    for current_low, current_high in sorted_ranges:
        if current_low <= high:
            high = max(high, current_high)
        else:
            #yield low, high
            merged_ranges.append((low, high))
            low  = current_low
            high = current_high
    #yield low, high
    merged_ranges.append((low, high))
    return frozenset(merged_ranges)


def getVARanges(noteSeg):
    if noteSeg:
        header = struct.Struct("<LLQQQQLLLLLLLLQLHH48s") # header shape for PROCSTAT_VMMAP (136 bytes)
        va_ranges = []
        for n in noteSeg.iter_notes():
            if n['n_type'] == 10: # FreeBSD PROCSTAT_VMMAP note type
                data = n.get('n_desc').encode('latin-1')[4:] # XXX No clue why there is a required offset of 4 bytes here to align...
                remaining = n['n_descsz']
                while remaining >= 136:
                    h, data = header.unpack(data[:136]), data[136:]
                    psz = h[0] - 136
                    s = "<{:d}s".format(psz)
                    path, data = struct.unpack(s, data[:psz]), data[psz:]
                    vmentry = FreeBSD_VMEntry(*h,path[0])
                    #print(vmentry)
                    remaining -= h[0]
                    va_ranges.append((
                            min(vmentry.kve_start,vmentry.kve_end),
                            max(vmentry.kve_start,vmentry.kve_end)))
            else:
                #print("skipping n_type {}".format(n['n_type']))
                pass
        return merge_ranges(va_ranges)
    else:
        return None


#################################
# scan individual coredump file #
#################################
# pickle helper
def odd():
    return OrderedDict()

def scanfile(fname):
    # open coredump
    cdump = openCoreDump(fname)
    if cdump:
        # build virtual address ranges
        va_ranges = getVARanges(cdump.notes)
        # scan individual segments
        workers = max(1,min(args.nb_processes,cdump.num_segments()))
        with multiprocessing.Pool(processes=workers) as pool:
        #with cf.ThreadPoolExecutor(max_workers=args.nb_processes) as pool:
            n = cdump.num_segments() - 1 if cdump.notes else cdump.num_segments()
            res = pool.map(scan,zip(range(1,n+1),[fname]*n,[va_ranges]*n))
        # handle results
        summary = defaultdict(odd)
        allPtrVectors = []
        for gs in args.group_sizes:
            summary['equal'][gs] = 0
            summary['zero'][gs] = 0
            summary['ptr'][gs] = 0
        total_size = 0
        for seg in res:
            idx, sz, chunks,eachPtrVector = seg
            allPtrVectors = allPtrVectors + eachPtrVector
            for gs in args.group_sizes:
                summary['equal'][gs] += chunks['equal'][gs]
                summary['zero'][gs] += chunks['zero'][gs]
                summary['ptr'][gs] += chunks['ptr'][gs]
            total_size += sz
        for gs in args.group_sizes:
            summary['equal'][gs] = summary['equal'][gs] * gs * 100 / total_size
            summary['zero'][gs] = summary['zero'][gs] * gs * 100 / total_size
            summary['ptr'][gs] = summary['ptr'][gs] * gs * 100 / total_size
        cdump.stream.close()
        return (fname,total_size,summary,allPtrVectors)

#################
# main function #
#################

def main():
    workers = max(1,min(int(args.nb_processes/2+1),len(args.coredumps)))
    print("workers = {}".format(workers))
    with cf.ProcessPoolExecutor(max_workers=workers) as pool:
        res = pool.map(scanfile,args.coredumps)
    for rpt in res:
        print("({}\ntotal size = {}\nequal\n{}\nzero\n{}\nptr\n{}".format(rpt[0],rpt[1],rpt[2]['equal'],rpt[2]['zero'],rpt[2]['ptr']))
        if args.dump_ptr_vector:
            with open(os.path.basename(rpt[0])+'.vecbin', 'wb') as eachOutput:
                counter = 0
                tempChar = 0
                for eachChar in rpt[3]:
                    if eachChar == "1":
                        tempChar |= 1<<counter
                    counter += 1
                    if counter == 8:
                        eachOutput.write(bytes([tempChar]))
                        counter = 0
                        tempChar = 0
    exit(0)

if __name__ == "__main__":
    main()
