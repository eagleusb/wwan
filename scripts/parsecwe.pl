#!/usr/bin/perl
#
# License: GPLv2
# Copyright 2016 Bjørn Mork <bjorn@mork.no>

use strict;
use warnings;
use Archive::Zip;
use Getopt::Long;

# data dump limit
my $datalimit = 8192;

sub usage {
    warn "Usage: $0 <file>\n";
    exit 0;
}

sub parse_flehdr {
    my $data = shift; # 256 bytes
    my $pfx = shift;
    my ($valid, $code, undef, $hdrsz, $imgsz, $type) = unpack("CCnNNA4", $data);
    print "${pfx}FLEHDR: $type: val=$valid, code=$code, hdrsz=$hdrsz, imgsz=$imgsz\n" if ($valid);
}

sub crc32 {
    my $buf = shift;
    my $crc = shift || 0xffffffff;
    $crc ^= 0xffffffff;
    $crc = Archive::Zip::computeCRC32($buf, $crc);
    return $crc ^ 0xffffffff;
}

# CWE use big endian integers!
sub parse_cwehdr {
    my $data = shift; # 400 bytes
    my $pfx = shift;
 
    my ($crc, $rev, $val, $type, $prod, $imgsz, $imgcrc, $version, $date, $compat, undef, $xxx) = unpack("NNA4A4A4NNa84a8Na16N", substr($data, 256));

    # assume a valid CWE header if the checksum of the first 256 bytes matches
    return (0) unless ($crc == &crc32(substr($data, 0, 256)));

    # make $val a 4byte string
    $val = "NOPE" if (unpack("N", $val) == 0xffffffff);

    &parse_flehdr(substr($data, 0, 256), $pfx);
    printf "${pfx}CWEHDR: $type: crc=0x%08x, rev=$rev, val=$val, prod=$prod, imgsz=$imgsz, imgcrc=0x%08x, date=$date, compat=0x%08x, xxx=0x%08x\n", $crc, $imgcrc, $compat, $xxx;

    # verify image crc
    my $crcok = &crc32(substr($data, 400, $imgsz)) == $imgcrc;
    printf "${pfx}  imgcrc %s, version string: '$version'\n", $crcok ? "OK" : "FAIL";

    return ($imgsz, $type);
}

# NVUPs use little endian integers! Confusing? Yes
sub parse_nvup {
    my $buf = shift;
    my $len = shift;
    my $pfx = shift || "";

# NVUP guessing:
# header data samples:
#   01 00 25 00 01 00 01 00 00 00 
#   01 00 8f 00 fe 00 01 00 00 00
#   01 00 03 00 05 00 01 00 00 00

# Confirmed:  $count matches the number of items found
    
    # NVUP header:
    my ($ver, $count, $foo, $bar) = unpack("vvvV", $buf);
    printf "${pfx}NVUP: $len bytes, ver=$ver, count=$count, foo=%04x, bar=%08x\n", $foo, $bar;
    $len -= 10;
    $buf = substr($buf, 10, $len);


# element sample (start):
#             87 02 00 00 02 00 01  00 01 00 19 00 00 00 00  |................|
#00002de0  2f 6e 76 75 70 2f 4e 56  55 50 5f 44 69 73 61 62  |/nvup/NVUP_Disab|
#00002df0  6c 65 42 35 2e 30 32 32  02 00 5a 02 00 00 00 00  |leB5.022..Z.....|
#00002e00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e10  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e20  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e30  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e40  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e50  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

# len=00000287 (le32)
# b=0002
# c=0001 (note! ref above)
# d=0001
# namelen=00000019
# flag=00
# name=/nvup/NVUP_DisableB5.022
#  data: 02 00 5a 02 00 00 00 00 ...
#      k=2 (le16, fixed?), datalen=0000025a (le32)

 
    my $number = 1;
    # parse each NVUP element
    while ($len > 0) {
	my ($l, $b, $c) = unpack("Vvv", $buf);
	printf "${pfx}  #%-03d %4d bytes: b=%04x, c=%04x", $number, $l, $b, $c;

	# set up for next element
	$number++;
	$len -= $l;
	
	# parse this element
	my $nvup = substr($buf, 8, $l - 8);

	# move buf ptr
	$buf = substr($buf, $l) if ($len > 0);
	
        # observed pattern:
	#  'name' is only valid if d==0001.  d might possibly indicate an NV entry number else?
	#  maybe we have a sequence of (d, len, val) entries for name, val?  I.e TLVs...
	# types:
	#    0001: name
	#    0002: value
	#    xxxx: nvitem
	while ($nvup) {
	    my ($d, $tlen) = unpack("vV", $nvup);
	    my $data = substr($nvup, 6, $tlen);
	    if ($d == 1) { # name of file or variable
		my ($flag, $name) = unpack("Ca*", $data);
		$data = ''; # consumed

		# observed pattern:
		#  switch (flag) {
		#    00: file
		#    02: weird entry - only a single 00 byte.  padding?
		#    08: named variable
		if ($flag == 2) {
		    $name = join(' ', map { sprintf "%02x", $_ } unpack("C*", $name));
		}
		printf ", <%02x> $name => ", $flag;
	    } elsif ($d == 2) { # value
		# observed pattern:
		#  data sometimes(?) contains a CWE header
		my $cwelen = &parse_cwe($data, $tlen, "${pfx}    ");
		$data = $cwelen ? substr($data, -$cwelen) : '';
	    } else { # nvitem
		# the NVITEM data is everything
		printf " NVITEM 0x%04x => ", $d;
	    }
	    print join(':', map { sprintf "%02x", $_ } unpack("C*", $data));
	    $nvup = substr($nvup, 6 + $tlen);
	}
	print "\n";
    }
}
	
# recursively parse an CWE file
sub parse_cwe {
    my $buf = shift;
    my $len = shift;
    my $pfx = shift || "";
 
    do {
	# get the size and type of any subimage
	my ($imgsz, $type, $crc) = &parse_cwehdr($buf, $pfx) if ($len >= 400);

	# we found the innermost data - return length to let parent know
	return $len unless $imgsz;

	# got a header: then read and parse that
	if ($len < $imgsz + 400) { # FIXME: buggy?
	    warn "no space for subimage in container: $len < $imgsz + 400\n";
	    return $len;
	}

	# strip away parsed header
	$len -= 400;
	$buf = substr($buf, 400);
	
	# recurse into the subimage
	my $innerlen = &parse_cwe($buf, $imgsz, "$pfx  "); 

	# $buf is pointing to the innermost data of the CWE - parse it according to type
	if ($innerlen > 0) {

	    # parse known formats
	    if ($type eq 'NVUP') {
		&parse_nvup($buf, $imgsz, "$pfx  ");
	    } else {
		printf "${pfx}  $type: $imgsz bytes\n" if 1; # redundant info
	    }
	}

	# strip the now parsed imgsz
	$len -= $imgsz;
	$buf = substr($buf, $imgsz) if ($len > 0);

    } while ($len > 0); # read next image at same level?

    # successfully parsed the buf
    return 0;
}    

my $x;
my $f = shift || &usage;
open(F, $f) || die $!;
my $size = (stat(F))[7];
my $n = read(F, $x, $size);
close(F);
&parse_cwe($x, $n);
exit 0;

# NVUP guessing:
# header data samples:
#   01 00 25 00 01 00 01 00 00 00 
#   01 00 8f 00 fe 00 01 00 00 00
#   01 00 03 00 05 00 01 00 00 00

# len=20
# b=00000001
# c=0001
# d=0001
# namelen=000a (10,  echo -n CARRIERID|wc -c => 9)
# type=00000008
# name=CARRIERID
#  data: 02 00 02 00 00 00  01 00
#      k=2 (le16, fixed?), datalen=2 (le32), data=1 (le16)


# len=0f
# b=00000000
# c=0001
# d=000b
# namelen=0f01  ( means that this is two 1-byte fields, len=1 implies null name)
# type=00000003

# len=0f
# b=00000000
# c=0001
# d=0070
# namelen=0301
# type=00000001

# len=0f
# b=00000000
# c=0001
# d=0072
# namelen=0301
# type=00000000

# len=11
# b=00000000
# c=0001
# d=000a
# namelen=0003
# type=00000000
# name=0400

# len=11
# b=00 00 00 00
# c=0001
# d=0050
# namelen=0303
# type=00000000
# name=00 00

# len=16
# b=00000000
# c=0001
# d=00a0
# namelen=1408
# type=00000001
# name=02 00 00 00 00 00 00

# len=11
# b=00000000
# c=0001
# d=0152
# namelen=0303
# type=00000000
# name=02 00

# len=0f
# b=00000000
# c=0001
# d=008d
# namelen=0301
# type=00000000

# len=10
# b=00000000
# c=0001
# d=00be
# namelen=0b02
# type=000000ff
# name=00


# len=46
# b=00000003
# c=0001
# d=0001
# namelen=0031 (49, echo -n /nv/item_files/modem/sms/store_to_sim_if_nv_full|wc -c => 48)
# type=00000001
# name=/nv/item_files/modem/sms/store_to_sim_if_nv_full
#  data: 02 00 01  00 00 00 01
#      k=2 (le16, fixed?), datalen=1 (le32), data=1 (u8)


# len=39
# b=00000003
# c=0001
# d=0001
# namelen=0024
# type=00000001
# name=/nv/item_files/modem/mmode/sm


#  From SWI9X30C_02.08.02.00/OEM/1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_001.003_000.nvu:
#00000620  31 32 2f 31 35 2f 31 35  00 00 00 01 00 00 00 00  |12/15/15........|
#00000630  00 00 00 00 00 00 00 00  00 00 00 00 50 61 72 73  |............Pars|
#00000640  01 00 8f 00 fe 00 01 00  00 00 10 00 00 00 80 00  |................|
#00000650  01 00 01 00 02 00 00 00  02 ff 40 00 00 00 01 34  |..........@....4|
#00000660  01 00 01 00 0c 00 00 00  08 50 52 4f 44 55 43 54  |.........PRODUCT|
#00000670  5f 53 4b 55 02 00 20 00  00 00 31 31 30 32 36 36  |_SKU.. ...110266|
#00000680  32 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |2...............|
#00000690  00 00 00 00 00 00 00 00  00 00 3f 00 00 00 01 34  |..........?....4|
#000006a0  01 00 01 00 0b 00 00 00  08 4e 56 50 52 49 49 44  |.........NVPRIID|

# => header data:
#  01 00 8f 00 fe 00 01 00  00 00


#00000960  e1 47 87 8a e7 28 e0 ba  ea 28 0b 25 00 00 00 01  |.G...(...(.%....|
#00000970  34 01 00 01 00 09 00 00  00 08 55 53 42 5f 43 4f  |4.........USB_CO|
#00000980  4d 50 02 00 08 00 00 00  01 00 00 00 0d 10 00 00  |MP..............|
#00000990  2a 00 00 00 01 34 01 00  01 00 15 00 00 00 08 43  |*....4.........C|

# len=25
# b=00000001
# c=3401 (note: all? variables in this file has c=3401, contrary to the carrier files)
# d=0001
# namelen=0009
# type=00000008
# name=USB_COMP
#  data: 02 00 08 00 00 00  01 00 00 00 0d 10 00 00
#      k=2 (le16, fixed?), datalen=8 (le32), data1=1 (le32), data2=0x0000100d (le32)


#  SWI9X30C_02.08.02.00/OEM/1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_001.003_000.nvu has multiple NVUP sections, where the last one seems to be part of a directory entry in the first one?


#00002dc0  72 67 65 74 5f 72 61 74  65 73 02 00 01 00 00 00  |rget_rates......|
#00002dd0  de 87 02 00 00 02 00 01  00 01 00 19 00 00 00 00  |................|
#00002de0  2f 6e 76 75 70 2f 4e 56  55 50 5f 44 69 73 61 62  |/nvup/NVUP_Disab|
#00002df0  6c 65 42 35 2e 30 32 32  02 00 5a 02 00 00 00 00  |leB5.022..Z.....|
#00002e00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e10  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e20  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e30  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e40  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e50  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e60  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e70  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e80  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002e90  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002ea0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002eb0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002ec0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002ed0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002ee0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#00002ef0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 f2 69  |...............i|
#00002f00  7a a7 00 00 00 03 47 4f  4f 44 4e 56 55 50 39 78  |z.....GOODNVUP9x|
#00002f10  33 30 00 00 00 ca 2c 89  29 0d 39 39 39 39 39 39  |30....,.).999999|
#00002f20  39 5f 39 39 30 31 32 33  34 5f 53 57 49 39 58 33  |9_9901234_SWI9X3|
#00002f30  30 43 5f 30 32 2e 30 35  2e 30 33 2e 30 30 5f 30  |0C_02.05.03.00_0|
#00002f40  30 5f 44 69 73 61 62 6c  65 42 35 5f 31 5f 30 30  |0_DisableB5_1_00|
#00002f50  30 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |0...............|
#00002f60  00 00 00 00 00 00 00 00  00 00 00 00 00 00 31 32  |..............12|
#00002f70  2f 30 38 2f 31 35 00 00  00 01 00 00 00 00 00 00  |/08/15..........|
#00002f80  00 00 00 00 00 00 00 00  00 00 50 61 72 73 01 00  |..........Pars..|
#00002f90  03 00 05 00 01 00 00 00  20 00 00 00 01 00 00 00  |........ .......|
#00002fa0  01 00 0a 00 00 00 08 43  41 52 52 49 45 52 49 44  |.......CARRIERID|
#00002fb0  02 00 02 00 00 00 05 00  3d 00 00 00 01 30 00 00  |........=....0..|
#00002fc0  01 00 19 00 00 00 08 50  45 52 4d 49 54 54 45 44  |.......PERMITTED|
#00002fd0  5f 43 41 52 52 49 45 52  5f 4c 54 45 5f 42 43 02  |_CARRIER_LTE_BC.|
#00002fe0  00 10 00 00 00 0a 10 00  00 00 00 00 00 00 00 00  |................|
#00002ff0  00 00 00 00 00 63 00 00  00 02 00 01 00 01 00 3f  |.....c.........?|
#00003000  00 00 00 00 2f 73 77 69  63 6f 6e 66 69 67 2f 30  |..../swiconfig/0|
#00003010  30 35 2f 69 74 65 6d 73  2f 73 77 69 6e 76 2f 69  |05/items/swinv/i|
#00003020  74 65 6d 5f 66 69 6c 65  73 2f 50 45 52 4d 49 54  |tem_files/PERMIT|
#00003030  54 45 44 5f 43 41 52 52  49 45 52 5f 4c 54 45 5f  |TED_CARRIER_LTE_|
#00003040  42 43 02 00 10 00 00 00  0a 10 00 00 00 00 00 00  |BC..............|
#00003050  00 00 00 00 00 00 00 00                           |........|
#00003058

#This shows tha the len field is more than one byte.  Possibly le32.
# len=00000287 (le32)
# b=02
# c=0001 (note! ref above)
# d=0001
# namelen=0019
# type=00000000
# name=/nvup/NVUP_DisableB5.022
#  data: 02 00 5a 02 00 00 00 00 ...
#      k=2 (le16, fixed?), datalen=0000025a (le32)


# => header data:
#  01 00 03 00 05 00 01 00 00 00
#
# ver=0001(le16), count=0003(le16), x=0005(le16) y=0000001(le32)

# types, or flags?
#  00000000 => dir
#  00000001 => file
#  00000003 => ???
#  00000008 => nvram var


## file system blocks?

__END__




my ($len, $b, $c, $d, $namelen, $type) = unpack("CNnnnN", );
my $name = substr(
my 

Fascinating:


bjorn@nemi:~/privat/prog/git/wwan/scripts$ dd if=/tmp/SWI9X30C_02.11.03.00_Generic_002.008_000.nvu bs=1 skip=1600|hexdump -vC >/tmp/b.txt
1444+0 records in
1444+0 records out
1444 bytes (1.4 kB) copied, 0.0194304 s, 74.3 kB/s
bjorn@nemi:~/privat/prog/git/wwan/scripts$ dd if=/tmp/SWI9X30C_02.08.02.00_Generic_002.007_000.nvu bs=1 skip=1600|hexdump -vC >/tmp/a.txt
1444+0 records in
1444+0 records out
1444 bytes (1.4 kB) copied, 0.0251198 s, 57.5 kB/s

bjorn@nemi:~/privat/prog/git/wwan/scripts$ diff -u /tmp/a.txt /tmp/b.txt 
--- /tmp/a.txt  2016-03-15 17:59:23.618909573 +0100
+++ /tmp/b.txt  2016-03-15 17:59:14.606758082 +0100
@@ -73,7 +73,7 @@
 00000480  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 00000490  00 00 00 00 00 00 00 00  44 00 00 00 01 00 01 00  |........D.......|
 000004a0  01 00 10 00 00 00 08 50  52 49 5f 43 41 52 52 49  |.......PRI_CARRI|
-000004b0  45 52 5f 52 45 56 02 00  20 00 00 00 30 32 30 37  |ER_REV.. ...0207|
+000004b0  45 52 5f 52 45 56 02 00  20 00 00 00 30 32 30 38  |ER_REV.. ...0208|
 000004c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 000004d0  00 00 00 00 00 00 00 00  00 00 00 00 0f 00 00 00  |................|
 000004e0  00 00 01 00 b3 03 01 00  00 00 00 59 00 00 00 03  |...........Y....|


00000640  01 00 25 00 01 00 01 00  00 00 20 00 00 00 01 00  |..%....... .....|
00000650  01 00 01 00 0a 00 00 00  08 43 41 52 52 49 45 52  |.........CARRIER|
00000660  49 44 02 00 02 00 00 00  01 00 0f 00 00 00 00 00  |ID..............|
00000670  01 00 0b 0f 01 00 00 00  03 0f 00 00 00 00 00 01  |................|
00000680  00 70 03 01 00 00 00 01  0f 00 00 00 00 00 01 00  |.p..............|
00000690  71 03 01 00 00 00 01 0f  00 00 00 00 00 01 00 72  |q..............r|
000006a0  03 01 00 00 00 00 11 00  00 00 00 00 01 00 0a 00  |................|
000006b0  03 00 00 00 00 04 00 11  00 00 00 00 00 01 00 50  |...............P|
000006c0  03 03 00 00 00 00 00 00  16 00 00 00 00 00 01 00  |................|
000006d0  a0 14 08 00 00 00 01 02  00 00 00 00 00 00 11 00  |................|
000006e0  00 00 00 00 01 01 52 03  03 00 00 00 00 02 00 0f  |......R.........|
000006f0  00 00 00 00 00 01 00 8d  03 01 00 00 00 00 10 00  |................|
00000700  00 00 00 00 01 00 be 0b  02 00 00 00 ff 00 46 00  |..............F.|
00000710  00 00 03 00 01 00 01 00  31 00 00 00 01 2f 6e 76  |........1..../nv|
00000720  2f 69 74 65 6d 5f 66 69  6c 65 73 2f 6d 6f 64 65  |/item_files/mode|
00000730  6d 2f 73 6d 73 2f 73 74  6f 72 65 5f 74 6f 5f 73  |m/sms/store_to_s|
00000740  69 6d 5f 69 66 5f 6e 76  5f 66 75 6c 6c 02 00 01  |im_if_nv_full...|
00000750  00 00 00 01 39 00 00 00  03 00 01 00 01 00 24 00  |....9.........$.|
00000760  00 00 01 2f 6e 76 2f 69  74 65 6d 5f 66 69 6c 65  |.../nv/item_file|
00000770  73 2f 6d 6f 64 65 6d 2f  6d 6d 6f 64 65 2f 73 6d  |s/modem/mmode/sm|

/* Sierra Wireless CWE file header 
 *   Note: 32bit numbers are big endian
 */
struct cwehdr {
	char reserved1[256];
	__u32 crc;		/* 32bit CRC of "reserved1" field */
	__u32 rev;		/* header revision */
	__u32 val;		/* CRC validity indicator */
	char type[4];		/* ASCII - not null terminated */
	char product[4];	/* ASCII - not null terminated */
	__u32 imgsize;		/* image size */
	__u32 imgcrc;		/* 32bit CRC of the image */
	char version[84];	/* ASCII - null terminated */
	char date[8];		/* ASCII - null terminated */
	__u32 compat;		/* backward compatibility */
	char reserved2[16];
	__u32 xxx;		/* 0x0000001 or 0x50617273  ("Pars") */
};

/* guessing "reserved1" */
struct filehdr {
	__u8 valid;		/* CWE: 00, NVU: 01 - all fields are 0 unless valid */
	__u8 code;		/* carrier_pri.nvu: 02, OEM/.nvu: 03 */
	__u16 resX;		/* 00 00 */
	__u32 hdrsize;		/* always 400? */
	__u32 imgsize;		/* identical to cwehdr imgsize */
	char type[4];		/* 'FULL' */
	char resY[240];		/* all 0 */
};

static int verify_filehdr(char *buf)
{
	struct filehdr *h = (void *)buf;
	char tmp[5];

	fprintf(stderr, " *** HDR ***\n");
	fprintf(stderr, "valid: %s\n", h->valid ? "yes" : "no");
	if (!h->valid)
		return 0;
	
	fprintf(stderr, "code: 0x%02x\n", h->code);
	fprintf(stderr, "header size: %d\n", be32toh(h->hdrsize));
	fprintf(stderr, "image size: %d\n", be32toh(h->imgsize));
	memcpy(tmp, h->type, 4);
	tmp[4] = 0;
	fprintf(stderr, "type: %s\n", tmp);
	return 0;
}
	
static int verify_cwehdr(char *buf)
{
	struct cwehdr *h = (void *)buf;
	char tmp[5];

	fprintf(stderr, " *** CWE ***\n");
	fprintf(stderr, "CWE revision: %d\n", be32toh(h->rev));
	fprintf(stderr, "crc: 0x%08x\n", be32toh(h->crc));
	memset(tmp, 0, sizeof(tmp));
	if (h->val != 0xffffffff)
		memcpy(tmp, &h->val, 4);
	fprintf(stderr, "CRC valid: %s\n", tmp);
	memcpy(tmp, h->type, 4);
	tmp[4] = 0;
	fprintf(stderr, "type: %s\n", tmp);
	memcpy(tmp, h->product, 4);
	tmp[4] = 0;
	fprintf(stderr, "product: %s\n", tmp);
	fprintf(stderr, "image size: %d\n", be32toh(h->imgsize));
	fprintf(stderr, "image crc: 0x%08x\n", be32toh(h->imgcrc));
	fprintf(stderr, "version: %s\n", h->version);
	fprintf(stderr, "date: %s\n", h->date);
	fprintf(stderr, "compat: 0x%08x\n", be32toh(h->compat));
	memcpy(tmp, &h->xxx, 4);
	tmp[4] = 0;
	fprintf(stderr, "xxx: 0x%08x ('%s')\n", be32toh(h->xxx), tmp);
	return (h->xxx == htobe32(0x0000001));
}

char *fourcc(char **b, const __u32 x)
{
	char *tmp = *b;
	
	*b += 5;
	memset(tmp, 0, 5);
	if (x != 0xffffffff)
		memcpy(tmp, &x, 4);
	else 
		memset(tmp, ' ', 4);
	return tmp;
}

static int hdrline()
{
	fprintf(stderr, "v code hdrsz imgsz rev hdrcrc  val type prod     size imgcrc   date     compat   xxx      version\n");
	return 0;
}

static int oneline(char *buf)
{
	struct filehdr *f = (void *)buf;
	struct cwehdr *h = (void *)buf;
	char *b, tmp[128];

	b = tmp;
	fprintf(stderr, "%c %02u %3u %8u %2u %08x %s %s %s %8u %08x %s %08x %08x %s\n",
		f->valid ? 'Y' : 'N',
		f->code,
		be32toh(f->hdrsize),
		be32toh(f->imgsize),
		be32toh(h->rev),
		be32toh(h->crc),
		fourcc(&b, h->val),
		fourcc(&b, *(__u32 *)h->type),
		fourcc(&b, *(__u32 *)h->product),
		be32toh(h->imgsize),
		be32toh(h->imgcrc),
		h->date,
		be32toh(h->compat),
		h->xxx,
		h->version);
	return h->xxx == htobe32(0x0000001);
}

static int dumpimage(const char *image)
{
	int imgfd = -1, ret = 0;
	struct stat img_data;
	char *buf = malloc(400);

	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	imgfd = open(image, O_RDONLY);
	if (imgfd < 0) {
		fprintf(stderr, "Cannot open %s: %d\n", image, imgfd);
		ret = imgfd;
		goto out;
	}
	fstat(imgfd, &img_data);
	hdrline();
	do {
		read(imgfd, buf, 400);
		ret = oneline(buf);
		/*
		verify_filehdr(buf);
		ret = verify_cwehdr(buf);
		*/
	} while (ret);
out:
	free(buf);
	if (imgfd > 0)
		close(imgfd);
	return ret;
}





Analyzing crc32 algorithm based on the common checksum for the 256 byte all zero "reserved1" block:

FLEHDR: FULL: val=1, code=2, hdrsz=400, imgsz=11072
CWEHDR: SPKG: crc=0x82d92888, rev=3, val=NOPE, prod=9X30, imgsz=11072, imgcrc=0xa980254f, date=01/07/16, compat=0x00000000, xxx=0x00000001
  (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')
  CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10672, imgcrc=0x0d2d42db, date=01/07/16, compat=0x00000000, xxx=0x00000001
    (version string: '')
    CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10272, imgcrc=0x02eee9fe, date=01/07/16, compat=0x01000000, xxx=0x00000001
      (version string: '/swir/nvdelta/NVUP_SPRINT.010')
      CWEHDR: NVUP: crc=0xf2697aa7, rev=3, val=GOOD, prod=9x30, imgsz=9872, imgcrc=0x5d57c7b9, date=01/07/16, compat=0x00000001, xxx=0x50617273
        (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')


bjorn@nemi:/tmp$ hexdump -C x
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000100


We got a match!:

bjorn@nemi:/tmp$ ./crc32 x
POLYNOMIAL=0x04c11db7, REVERSED_DATA=0, REVERSED_OUT=0 INITIAL_VALUE=0xffffffff, FINAL_XOR_VALUE=0x00000000
Result: 0xf2697aa7


And even more important, we can match the "imgcrc":

bjorn@nemi:/tmp$ ~/privat/prog/git/wwan/scripts/parsecwe.pl  ~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu 
FLEHDR: FULL: val=1, code=2, hdrsz=400, imgsz=11072
CWEHDR: SPKG: crc=0x82d92888, rev=3, val=NOPE, prod=9X30, imgsz=11072, imgcrc=0xa980254f, date=01/07/16, compat=0x00000000, xxx=0x00000001
  (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')
  CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10672, imgcrc=0x0d2d42db, date=01/07/16, compat=0x00000000, xxx=0x00000001
    (version string: '')
    CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10272, imgcrc=0x02eee9fe, date=01/07/16, compat=0x01000000, xxx=0x00000001
      (version string: '/swir/nvdelta/NVUP_SPRINT.010')
      CWEHDR: NVUP: crc=0xf2697aa7, rev=3, val=GOOD, prod=9x30, imgsz=9872, imgcrc=0x5d57c7b9, date=01/07/16, compat=0x00000001, xxx=0x50617273
        (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')
bjorn@nemi:/tmp$ dd  if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu bs=256 count=1 of=y
1+0 records in
1+0 records out
256 bytes (256 B) copied, 0.00141891 s, 180 kB/s
bjorn@nemi:/tmp$ ls -la ~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu 
-rw-r--r-- 1 bjorn bjorn 11472 Jan 19 01:59 /home/bjorn/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu
bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu skip=1600 bs=1 of=y
9872+0 records in
9872+0 records out
9872 bytes (9.9 kB) copied, 0.084083 s, 117 kB/s
bjorn@nemi:/tmp$ ./crc32 y
POLYNOMIAL=0x04c11db7, REVERSED_DATA=0, REVERSED_OUT=0 INITIAL_VALUE=0xffffffff, FINAL_XOR_VALUE=0x00000000
Result: 0x5d57c7b9



The only difference from the algo as implemented in the crc32 util (from Zip) is the REVERSED_OUT:

bjorn@nemi:~/privat/prog/git/wwan/scripts$ ./crc32 /tmp/x
POLYNOMIAL=0x04c11db7, REVERSED_DATA=0, REVERSED_OUT=1 INITIAL_VALUE=0xffffffff, FINAL_XOR_VALUE=0x00000000
Result: 0xd968558
bjorn@nemi:~/privat/prog/git/wwan/scripts$ crc32 /tmp/x
0d968558




So: how do we convert 0xd968558 to 0xf2697aa7 ?


1111 0010 0110 1001  0111 1010 1010 0111  vs 0000 1101 1001 0110 1000 0101 0101 1000

Doh! that's just all bits inverted...

Adding

    $crc = ~$crc & 0xffffffff;

to the default /usr/bin/crc32 script makes it produce the correct result:

bjorn@nemi:~/privat/prog/git/wwan/scripts$ ./crc32.pl /tmp/x
f2697aa7

bjorn@nemi:~/privat/prog/git/wwan/scripts$ ./crc32.pl /tmp/y
5d57c7b9


Or as a one-liner. reading from stdin:

 perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; $crc = ~$crc & 0xffffffff; printf( "0x%08x\n", $crc )' </tmp/x
0xf2697aa7

bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu skip=1600 bs=1 | perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; printf( "0x%08x\n", ~$crc  & 0xffffffff)'
9872+0 records in
9872+0 records out
9872 bytes (9.9 kB) copied, 0.0669251 s, 148 kB/s
0x5d57c7b9


Note:  It seems all the imgcrcs are actually valid, regardless of the NOPE/GOOD status:


bjorn@nemi:/tmp$ ~/privat/prog/git/wwan/scripts/parsecwe.pl ~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu
FLEHDR: FULL: val=1, code=2, hdrsz=400, imgsz=11072
CWEHDR: SPKG: crc=0x82d92888, rev=3, val=NOPE, prod=9X30, imgsz=11072, imgcrc=0xa980254f, date=01/07/16, compat=0x00000000, xxx=0x00000001
  (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')
  CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10672, imgcrc=0x0d2d42db, date=01/07/16, compat=0x00000000, xxx=0x00000001
    (version string: '')
    CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=10272, imgcrc=0x02eee9fe, date=01/07/16, compat=0x01000000, xxx=0x00000001
      (version string: '/swir/nvdelta/NVUP_SPRINT.010')
      CWEHDR: NVUP: crc=0xf2697aa7, rev=3, val=GOOD, prod=9x30, imgsz=9872, imgcrc=0x5d57c7b9, date=01/07/16, compat=0x00000001, xxx=0x50617273
        (version string: '9999999_9904779_SWI9X30C_02.08.02.00_00_SPRINT_000.012_000')
bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu skip=1200 bs=1 | perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; printf( "0x%08x\n", ~$crc  & 0xffffffff)'
10272+0 records in
10272+0 records out
10272 bytes (10 kB) copied, 0.0694174 s, 148 kB/s
0x02eee9fe
bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu skip=800 bs=1 | perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; printf( "0x%08x\n", ~$crc  & 0xffffffff)'
10672+0 records in
10672+0 records out
10672 bytes (11 kB) copied, 0.0739627 s, 144 kB/s
0x0d2d42db
bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/carrier_pri.nvu skip=400 bs=1 | perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; printf( "0x%08x\n", ~$crc  & 0xffffffff)'
11072+0 records in
11072+0 records out
11072 bytes (11 kB) copied, 0.0759387 s, 146 kB/s
0xa980254f






bjorn@nemi:/tmp$ ~/privat/prog/git/wwan/scripts/parsecwe.pl ~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/spkg_sblz.cwe 
CWEHDR: SPKG: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=64204473, imgcrc=0x037d715c, date=01/06/16, compat=0x00000001, xxx=0x00000001
  (version string: 'INTERNAL_?_SWI9X30C_02.08.02.00_?_?_?_?')
Negative length at /home/bjorn/privat/prog/git/wwan/scripts/parsecwe.pl line 49.


This took a bit of time, but ended up with the expected sum:

bjorn@nemi:/tmp$ dd if=~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/3/spkg_sblz.cwe skip=400 bs=1 | perl -MArchive::Zip -e 'my $buf; my $crc = 0; while (read(*STDIN, $buf, 32768)) { $crc = Archive::Zip::computeCRC32($buf, $crc); }; printf( "0x%08x\n", ~$crc  & 0xffffffff)'
64204473+0 records in
64204473+0 records out
64204473 bytes (64 MB) copied0x037d715c
, 795.249 s, 80.7 kB/s
