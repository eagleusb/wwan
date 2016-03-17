#!/usr/bin/perl
#
# License: GPLv2
# Copyright 2016 Bjørn Mork <bjorn@mork.no>

use strict;
use warnings;
use Archive::Zip;
use Getopt::Long;

# fixed prod
my $prod = "9X30";

# fixed version string;
my $ver = "9999999_9904609_SWI9X30C_00.00.00.00_00_bjorn_001.000_000";
    
## test with a legal value first! my $usbcomp = 0x0000050f; # (diag,adb,nmea,modem,rmnet0,rmnet1) 
my $usbcomp = 0x0000010d; # (diag,nmea,modem,rmnet0) 

#  supported values are:
#
# AT!USBCOMP=<Config Index>,<Config Type>,<Interface bitmask>
#  <Config Index>      - configuration index to which the composition applies, should be 1
#
#  <Config Type>       - 1:Generic, 2:USBIF-MBIM, 3:RNDIS
#                        config type 2/3 should only be used for specific Sierra PIDs: 68B1, 9068
#                        customized VID/PID should use config type 1
#
#  <Interface bitmask> - DIAG     - 0x00000001,
#                        NMEA     - 0x00000004,
#                        MODEM    - 0x00000008,
#                        RMNET0   - 0x00000100,
#                        RMNET1   - 0x00000400,
#                        MBIM     - 0x00001000,
#  e.g.
#  10D  - diag, nmea, modem, rmnet interfaces enabled
#  1009 - diag, modem, mbim interfaces enabled
#
#  The default configuration is:
#  at!usbcomp=1,1,10F'

#bjorn@nemi:~/privat/prog/git/wwan/scripts$ ./parsecwe.pl ~/docs/hardware/sierra/em7455/firmware/SWI9X30C_02.08.02.00/OEM/1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_#001.003_000.nvu 
#FLEHDR: FULL: val=1, code=3, hdrsz=400, imgsz=11976
#CWEHDR: SPKG: crc=0x69d98b86, rev=3, val=NOPE, prod=9X30, imgsz=11976, imgcrc=0x3a9b2ec2, date=12/15/15, compat=0x00000000, xxx=0x00000001
#  imgcrc OK, version string: '1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_001.003_000'
#  CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=11576, imgcrc=0x79e48690, date=12/15/15, compat=0x00000000, xxx=0x00000001
#    imgcrc OK, version string: '1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_001.003_000'
#    CWEHDR: FILE: crc=0xf2697aa7, rev=3, val=NOPE, prod=9X30, imgsz=11176, imgcrc=0xe788bc00, date=12/15/15, compat=0x01000000, xxx=0x00000001
#      imgcrc OK, version string: '/nvup/NVUP_1102662_EM7455_Lenovo-Laptop.020'
#      CWEHDR: NVUP: crc=0xf2697aa7, rev=3, val=GOOD, prod=9x30, imgsz=10776, imgcrc=0x33ff014e, date=12/15/15, compat=0x00000001, xxx=0x50617273
#        imgcrc OK, version string: '1102662_9905046_EM7455_02.05.07.00_00_Lenovo-Laptop_001.003_000'
#        NVUP: 10776 bytes, ver=1, count=143, foo=00fe, bar=00000001
#          #1     16 bytes: b=0080, c=0001, <02> ff => 
#
#          #14    37 bytes: b=3401, c=0001, <08> USB_COMP => 01:00:00:00:0d:10:00:00


# goal: try to create a minimum NV diff file, setting USB_COMP to the chosen value
# strategy: start from the inside, and build header data around until finished


sub crc32 {
    my $buf = shift;
    my $crc = shift || 0xffffffff;
    $crc ^= 0xffffffff;
    $crc = Archive::Zip::computeCRC32($buf, $crc);
    return $crc ^ 0xffffffff;
}

sub mkfilehdr {
    my $imgsz = shift;
    return pack("CCnNNa[244]",1, 3, 0, 400, $imgsz, "FULL");
}

sub mkcwehdr {
    my ($type, $version, $compat, $xxx, $image) = @_;

    
    my ($mday, $mon, $year) = (localtime)[3,4,5];
    $year -= 100;
    $mon++;
    my $date = sprintf "%02d/%02d/%02d", $mon, $mday, $year;
    my $imgsz = length($image);
    my $reserved = $type eq 'SPKG' ? &mkfilehdr($imgsz) : pack("a[256]", '');
    my $val = $type eq 'NVUP' ? 'GOOD' : pack("N", 0xffffffff);

    my $imgcrc = &crc32($image);
    my $crc = &crc32($reserved);

    return $reserved . pack("NNA4A4A4NNa84a8Na16N", $crc, 3, $val, $type, $prod, $imgsz, $imgcrc, $version, $date, $compat, '', $xxx) . $image;
}

# start from the back: value TLV, name TLV, NVUP entry, NVUP header, 
sub mknvup {
    my $valtlv = pack("vVVV", 2, 8, 1, $usbcomp); # type=2, len=8, data = 0x0000001, $usbcomp
    my $name = "USB_COMP";
    my $keytlv = pack("vVCa*", 1, length($name) + 1, 8, $name);
    my $len = 8 + length($keytlv) +  length($valtlv);
    my $entry = pack("Vvv", $len, 1, 1);  # typical values

    # header ($ver, $count, $foo, $bar)
    return pack("vvvV", 1, 1, 1, 1).  # typical values, except for count which is fixed at 1 here
	$entry . $keytlv . $valtlv;
}


my $image = &mknvup();
my $cwe = &mkcwehdr('NVUP', $ver, 0x00000001, 0x50617273, $image);
$cwe = &mkcwehdr('FILE', '/swir/nvdelta/NVUP_bjorn.020', 0x01000000, 0x00000001, $cwe);
$cwe = &mkcwehdr('FILE', $ver, 0x00000000, 0x00000001, $cwe);
$cwe = &mkcwehdr('SPKG', $ver, 0x00000000, 0x00000001, $cwe);
print $cwe;
