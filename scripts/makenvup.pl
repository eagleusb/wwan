#!/usr/bin/perl
#
# License: GPLv2
# Copyright 2016 Bjørn Mork <bjorn@mork.no>

use strict;
use warnings;
use Archive::Zip;
use Getopt::Long;

my $prod = "9X30";
my $fname = "BJORN";
my $imgver = "00.00.00.00";  # match any?

my $ver = "INTERNAL_9901234_SWI${prod}C_${imgver}_00_${fname}_000.000_000";

## test with a legal value first! 
##my $usbcomp = 0x0000050d; # (diag,nmea,modem,rmnet0,rmnet1) 
##my $usbcomp = 0x0000050f; # (diag,adb,nmea,modem,rmnet0,rmnet1)
my $usbcomp = 0x0000100f; # (diag,adb,nmea,modem,mbim)

# Yeeha!  after adding
#
# nemi:/home/bjorn# cat /root/.android/adb_usb.ini 
# # ANDROID 3RD PARTY USB VENDOR ID LIST -- DO NOT EDIT.
# # USE 'android update adb' TO GENERATE.
# # 1 USB VENDOR ID PER LINE.
# 0x1199
#
# we got liftoff:
#
# nemi:~# adb devices
# List of devices attached 
# LQ53740015020204        device
#
# nemi:~# adb shell
# / # uname -a
# Linux mdm9635-perf 3.10.0+ #1 PREEMPT Wed Jan 6 21:51:50 PST 2016 armv7l GNU/Linux


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

## more complete help text taken from memory dump:

#AT!USBCOMP=<Config Index>,<Config Type>,<Interface bitmask>
#  <Config Index>      - configuration index to which the composition applies, should be 1
#  <Config Type>       - 1:Generic, 2:USBIF-MBIM, 3:RNDIS
#                        config type 2/3 should only be used for specific Sierra PIDs: 68B1, 9068
#                        customized VID/PID should use config type 1
#  <Interface bitmask> - DIAG     - 0x00000001,
#                        ADB      - 0x00000002,
#                        NMEA     - 0x00000004,
#                        MODEM    - 0x00000008,
#                        RMNET0   - 0x00000100,
#                        RMNET1   - 0x00000400,
#                        RMNET2   - 0x00000800,
#                        MBIM     - 0x00001000,
#                        RNDIS    - 0x00004000,
#                        AUDIO    - 0x00010000,
#                        ECM      - 0x00080000,
#                        UBIST    - 0x00200000
#  e.g.
#  10D  - diag, nmea, modem, rmnet0 interfaces enabled
#  1009 - diag, modem, mbim interfaces enabled
#  The default configuration is:
#  at!usbcomp=1,1,10F

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
    return pack("CCnNNa[244]",1, 3, 0, 400, $imgsz, "FULL");  # the meaning of 'code' is uncertain.  OEM file has 3, others have 2.
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
$cwe = &mkcwehdr('FILE', "/nvup/NVUP_${fname}.020", 0x01000000, 0x00000001, $cwe);
$cwe = &mkcwehdr('FILE', $ver, 0x00000000, 0x00000001, $cwe);
$cwe = &mkcwehdr('SPKG', $ver, 0x00000000, 0x00000001, $cwe);
print $cwe;




__END__

Interesting variables:



          #7     45 bytes: b=3401, c=0001, <08> ATLOWPWD => 14:62:64:65:00:00:00:00:00:00:00:00:00:00:00:00
          #8     36 bytes: b=3401, c=0001, <08> ANTITHEFT_MODE => 00
          #9     30 bytes: b=3401, c=0001, <08> FCC_AUTH => 00
          #10    36 bytes: b=3401, c=0001, <08> USB_VENDOR_ID => 3c:41
          #11    42 bytes: b=3401, c=0001, <08> USB_APP_BOOT_PIDS => b6:81:b5:81
          #12    98 bytes: b=3401, c=0001, <08> USB_PROD_NAME => 44:57:35:38:31:31:65:20:53:6e:61:70:64:72:61:67:6f:6e:e2:84:a2:20:58:37:20:4c:54:45:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
          #13    46 bytes: b=3401, c=0001, <08> FWID_GUID => 6e:db:47:5a:e0:b4:4a:42:97:50:1e:c6:4f:05:fd:13
          #14    37 bytes: b=3401, c=0001, <08> USB_COMP => 01:00:00:00:0d:10:20:00
          #15    42 bytes: b=3401, c=0001, <08> CUST_USBSERIALENABLE => 01
          #16    37 bytes: b=3401, c=0001, <08> CUST_FASTENUMEN => 00
          #17    36 bytes: b=3401, c=0001, <08> CUST_GPSENABLE => 01
          #18    35 bytes: b=3401, c=0001, <08> CUST_GPSLPMEN => 00
          #19    33 bytes: b=3401, c=0001, <08> CUST_GPSSEL => 01
          #20    35 bytes: b=3401, c=0001, <08> GPS_AUTOSTART => 02
          #21    41 bytes: b=3401, c=0001, <08> GPS_MTLR_NOTIF_RESP => 01
          #22    36 bytes: b=3401, c=0001, <08> GNSS_ANT_POWER => 00
          #23    33 bytes: b=3401, c=0001, <08> CUST_SIMLPM => 01
          #24    31 bytes: b=3401, c=0001, <08> W_DISABLE => 00
          #25    37 bytes: b=3401, c=0001, <08> CUST_WAKEHOSTEN => 00




Wonder about the "ATLOWPWD".  It is the same value in all OEM files.
Thinking about the well known "A710" password...  Doesn't that map nicely to 
14:62:64:65?  if we just subtract the values from a known offset?

A710 => 41:37:31:30

The sum is 55:95:95:95.  Not quite it...  There is something else to this.
