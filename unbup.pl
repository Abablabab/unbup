#!/usr/bin/env perl
# Forked from https://github.com/OpenSecurityResearch/unbup 
# (Tony Lee and Travis Rosiek)

use strict;
use File::Copy;
use Getopt::Long;

use Data::Dumper;

my $help_text = <<HELP;
unpub v1.1
Retreives binary details and (optionally) original binaries from BUP files
Usage:  $0 [option] <file.bup>

    options:
    -h  --help                  Display this message
    -d  --details-only          Only extract the details of the BUP file
    -r  --restore-filenames     Restore original filenames 
                                (otherwise BUP name will be used)
HELP

my $szbin = `which 7z`;
chomp $szbin;
if (!$szbin) {
    die "Could not find 7z. please make sure 7z is in your path";
}

my ($help, $details, $restore, $filename);
Getopt::Long::GetOptions(   
    'help'              => \$help,
    'details-only'      => \$details,
    'restore-filenames' => \$restore,
);
my $filename = $ARGV[0] or $help = 1;
chomp $filename;

if ($help) {
    print $help_text;
    exit();
}

# Open the file, mandatory for all options
open (my $file, '<', $filename) or die "Could not open $filename\n@!";

my $bupname = $filename;
$bupname =~ s/(.+) \. bup/$1/xi;

# Extract the Details from the OLE container and decrypt them
my $enc_details = `$szbin e -so $filename Details 2>/dev/null` or 
    die "Couldn't execute 7z\n";
my $pt_details = decode( $enc_details );

# Retrieve the original name in case we want that
my $org_name = get_original_name( $pt_details );

if ($restore) {
    write_file( $pt_details, "$org_name.details" );
} else {
    write_file( $pt_details, "$bupname.details" );
}

if ($details) {
    # We don't want any more stuff, so we're done
    exit();
}

# If we're still here we want more
my $enc_binary = `$szbin e -so $filename File_0 2>/dev/null` or 
    die "Couldn't execute 7z\n";
my $binary = decode( $enc_binary );

if ($restore) {
    write_file( $pt_details, "$org_name" );
} else {
    write_file( $pt_details, "$bupname.binary" );
}

sub decode {
    my @chars = split('',shift);
    my @decoded;
    for (@chars) {
        $_ = $_ ^ 'j'; # 0x6A
        push ( @decoded, $_ );
    }
    return join( '', @decoded );
}

sub write_file {
    my ($content, $name) = @_;
    open (my $fh, '>', $name) or die "couldn't open $name to write!";
    print $fh $content;
    close $fh;
    print "$name extracted OK\n";
}

sub get_original_name {
    my $details = shift;
    my ($line) = $details =~ m/(OriginalName.+?\r\n)/m;
    my ($name) = $line =~ m/.+\\(.+?)\r\n/m;
    return $name;
}
