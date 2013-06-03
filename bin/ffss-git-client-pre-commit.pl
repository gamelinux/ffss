#!/usr/bin/perl 
# ----------------------------------------------------------------------
#
# Copyright (C) 2013 Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);

my $RULESDIR= "rules/"; 
my $VERBOSE = 0;
my $DEBUG   = 0;
my $GID     = 1;

my $rules = {};
my $nextsid = 9000000;

sub get_highest_sid (\%) {
    my $hash = shift;
    my $big  = 0;

    foreach my $sid (keys %$hash) {
      if ( $sid > $big ) {
        $big = $sid;
      }
    }
    return $big;
}

$rules = parse_all_rule_files($RULESDIR,$rules,$VERBOSE,$DEBUG);
my $sids = {};
$sids = $rules->{1};
$nextsid = get_highest_sid(%$sids) + 1 ;
print "[*] Next sid is: ". $nextsid ."\n";
exit (0);

=head1 FUNCTIONS

=head2 parse_all_rule_files

 Opens all the rule files, parses them, and stors rules in a hash

=cut

sub parse_all_rule_files {
    my ($RULESDIR,$NRULEDB,$VERBOSE,$DEBUG) = @_;
    my @FILES;

    # Open the directory
    print "[*] Looking for rulefiles in $RULESDIR\n";
    if( opendir( DIR, "$RULESDIR/" ) ) {
       # Find rule files in dir (*.rules)
       while( my $FILE = readdir( DIR ) ) {
          next if( ( "." eq $FILE ) || ( ".." eq $FILE ) );
          next unless ($FILE =~ /.*\.rules$/);
          push( @FILES, $FILE ) if( -f "$RULESDIR$FILE" );
       }
       closedir( DIR );
    } else {
        print "[E] Error opening dir: $RULESDIR\n";
        return;
        #exit 1;
    }
    foreach my $FILE ( @FILES ) {
       $NRULEDB = get_rules ("$RULESDIR/$FILE",$NRULEDB,$VERBOSE,$DEBUG);
       if ( $NRULEDB->{1}->{0}->{'OK'} == 0 ) {
          print "[E] Error when parsing $RULESDIR$FILE: $!\n";
          exit (1);
       }
    }
    print "[*] Processed ". $NRULEDB->{1}->{0}->{'count'} ." Rules.\n" if defined $NRULEDB->{1}->{0}->{'count'};
    return $NRULEDB;
}

=head2 get_rules

 This sub extracts the rules from a rules file.
 Takes $file as input parameter.

=cut

sub get_rules {
  my ($RFILE,$NRULEDB,$VERBOSE,$DEBUG) = @_;
  $NRULEDB->{1}->{0}->{'OK'} = 0;

  if (open (FILE, $RFILE)) {
    my ($rulegroup) = ($RFILE =~ /\/([-\w]+)\.rules$/);
    print "[*] Verifying rules in file: ".$RFILE."\n" if ($DEBUG || $VERBOSE);
    # Verify the data in the session files
    LINE:
    while (my $rule = readline FILE) {
      chomp $rule;
      my $rfields = {};

      next LINE unless($rule); # empty line
      next LINE if ($rule =~ /^\#$/);

      $rfields = verify_rule($rule,$RFILE);
      if ($rfields->{'OK'} == 0) {
        next LINE;
      }

      my $sid = $rfields->{'sid'};
      if ( defined $NRULEDB->{1}->{$sid} ) {
        print "[E] The sid:$sid is a dupe! '$RFILE' Skipping!\n";
        next LINE;
      }

      $NRULEDB->{1}->{$sid} = $rfields;
      $NRULEDB->{1}->{0}->{'OK'} = 1;
      $NRULEDB->{1}->{0}->{'count'}++;
    }
    close FILE;
  }
  return $NRULEDB;
}

sub verify_rule() {
  my ($rule,$RFILE) = @_;
  my $rf = {};
  $rf->{OK} = 0;

  return $rf if not ( $rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)\s*$/);
  ($rf->{'action'}, $rf->{'proto'}, $rf->{'sip'}, $rf->{'sport'}, $rf->{'dir'}, $rf->{'dip'}, $rf->{'dport'}, $rf->{'options'}) = ($1, $2, $3, $4, $5, $6, $7, $8);

  #$rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/;
  #my ($action, $proto, $sip, $sport, $dir, $dip, $dport, $options) = ($1, $2, $3, $4, $5, $6, $7, $8);

  unless($rule) {
    print "[E] Error: Not a valid rule in: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  if ( $rule =~ / $/ ) {
    print "[E] Error: Rule has trailing whitespaces: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  if (not defined $rf->{'options'}) {
    print "[E] Error: Options missing in rule: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  # ET rules has: "sid: 2003451;"
  unless( $rf->{'options'} =~ /sid:\s*([0-9]+)\s*;/ ) {
    print "[E] No sid found in rule options: '$RFILE'\n";
    print "[D] RULE: $rf->{'options'}\n" if $DEBUG;
    return $rf;
  }
  $rf->{'sid'} = $1;

  $rf->{'options'} =~ /msg:\s*\"(.*?)\"\s*;/;
  $rf->{'msg'} = $1;

  $rf->{'options'} =~ /rev:\s*(\d+?)\s*;/;
  $rf->{'rev'} = $1;

  # This also removes comments in rules (making them active)
  #if ( $rule =~ s/^# ?//g ) {
  #  $rf->{'enabled'} = 0;
  #} else {
  #  $rf->{'enabled'} = 1;
  #}

  # Check some basic orders, so we are consistent in our rules:
  unless ( $rf->{'options'} =~ /msg:.*metadata:.*classtype:.*sid:.*rev:/ ) {
    print "[E] Rule optionorder inconsistency for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] Should be: (msg:.*metadata:.*classtype:.*sid:.*rev:)\n" if $DEBUG;
    return $rf;
  }

  # Check some other personal preferences for consistency
  # "(content|dsize|flowint|flowbits|stream_size|reference|metadata):"
  if ( $rf->{'options'} =~ /flow:\s*([\w,]+)\s*;/ ) {
    my $flow = $1;
    if ( $flow =~ /(from_server|from_client)/ ) {
      print "[E] flow option inconsistency (use to_server/to_client) for sid:". $rf->{'sid'} .": '$RFILE'\n";
      print "[D] RULE: $rule\n" if $DEBUG;
      return $rf;
    }
    if ( $flow =~ /_(server|client).*(established|stateless)/ ) {
      print "[E] flow option inconsistency (use state before direction) for sid:". $rf->{'sid'} .": '$RFILE'\n";
      print "[D] RULE: $rule\n" if $DEBUG;
      return $rf;
    }
  }

  # Error if we see common cases of missing space, like ";keyword:" 
  if ( $rf->{'options'} =~ /;(msg|flow|content|dsize|flowint|flowbits|stream_size|reference|metadata|sid|rev):/ ) {
    print "[E] Possible missing space between keyword ($1) and option for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
  }

  # Error if we see common cases of extra space, like "keyword: option" 
  if ( $rf->{'options'} =~ /(msg|flow|content|dsize|flowint|flowbits|stream_size|reference|metadata|sid|rev): / ) {
    print "[E] Possible extra space between keyword ($1) and option for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
  }

  # My way of writing metadata should be there, else fail!
  unless ( $rf->{'options'} =~ / metadata:\s*(.*)\s*; classtype:/ ) {
    print "[E] Metadata missing/b0rked for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }
  $rf->{'metadata'} = $1;

  # Now pick the metadata appart!
  # author acronyme-user, dengine snort-2.9.4, tlp white, type banker, killchain c2, intrusionset poetlovers, date_created 2013-01-01, date_modified 2013-01-12
  unless ( $rf->{'metadata'} =~ /^author (.+), dengine (.+), tlp (.+), type (.+), killchain (.+), intrusionset (.+), enabled (.+), date_created (.+), date_modified (.+)$/ ) {
    print "[E] Metadata b0rked for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }
  ($rf->{'author'}, $rf->{'dengine'}, $rf->{'tlp'}, $rf->{'type'}, $rf->{'killchain'}, $rf->{'intrusionset'}, $rf->{'enabled'}, $rf->{'date_created'}, $rf->{'date_modified'})
      = ($1, $2, $3, $4, $5, $6, $7, $8, $9);

  # Check for valid TLP color :)
  unless ( $rf->{'tlp'} =~ /^(white|green|amber|red)$/ ) {
    print "[E] Invalid TLP: ". $rf->{'tlp'} ." for sid:". $rf->{'sid'} .":'$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  # Check for more or less valid dengine
  unless ( $rf->{'dengine'} =~ /^((snort|suricata)-(\d\.\d{1,2}(\.\d{1,2})?))$/ ) {
    print "[E] Invalid dengine: ". $rf->{'dengine'} ." for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  # Check for valid KillChain state
  unless ( $rf->{'killchain'} =~ /^(reconnaissance|weaponization|delivery|exploitation|installation|c2|actions|none)$/ ) {
    print "[E] Invalid killchain entry: ". $rf->{'killchain'} ." for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  unless ( $rf->{'date_created'} =~ /^\d\d\d\d-\d\d-\d\d$/ ) {
    print "[E] Invalid date_created: " .$rf->{'date_created'} ." for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  unless ( $rf->{'date_modified'} =~ /^\d\d\d\d-\d\d-\d\d$/ ) {
    print "[E] Invalid date_modified: ". $rf->{'date_created'} ." for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  unless ( $rf->{'enabled'} =~ /^(yes|no)$/ ) {
    print "[E] Invalid state for enabled: ". $rf->{'enabled'} ." for sid:". $rf->{'sid'} .": '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    return $rf;
  }

  $rf->{'gsrmd5'} = md5_hex("$GID:$rf->{'sid'}:$rf->{'rev'}");
  $rf->{'rmd5'} = md5_hex("$rule");

  $rf->{OK} = 1;
  return $rf;
}

