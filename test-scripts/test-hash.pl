#!/usr/bin/perl -w

my $hash = chr(0x73) . chr(0x65) . chr(0x63) . chr(0x72) . chr(0x65) . chr(0x74) . chr(0x6B) . chr(0x65) . chr(0x79) . chr(0x61) . chr(0x64) . chr(0x6D) . chr(0x69) . chr(0x6E) . chr(0x3D) . chr(0x31) .
chr(0x80) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) .
chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) .
chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00);

for(my $i = 0; $i < 256; $i++) {
  open TEMP, ">temp";

  print TEMP $hash;
  print TEMP chr($i);
  close TEMP;
  print $i . " " . `sha1sum temp`;
}

unlink("temp");