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
#
# This file is a part of ffss. This file should be placed in:
#  /usr/local/bin/ffss-git-server-pre-commit.pl
# on the git server. This script is intended to be called by
# the ffss pre-receive script: ffss-git-server-pre-receive.sh
# 
use strict;
use warnings;
use MongoDB;
use MongoDB::OID;
use Digest::MD5 qw(md5_hex);
use Getopt::Long;

# Defaults, no need to change.
my $MONGOTBL= "rules";
my $RULESDIR= "rules/"; 

my $VERBOSE = 0;
my $DEBUG   = 0;
my $GID     = 1;

GetOptions ("dbname=s" => \$MONGOTBL);
my $MONGOTBL_C = $MONGOTBL ."_current";

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

$^W = 1;

our $conn = MongoDB::Connection->new(host => $MONGOHOST);
$rules = parse_all_rule_files($RULESDIR,$rules,$VERBOSE,$DEBUG);
my $sids = {};
$sids = $rules->{1};
push_to_mongodb($sids);
$nextsid = get_highest_sid(%$sids);
$nextsid++;
print "[*] Next sid is: ". $nextsid ."\n";
update_current_rules_mongodb();
exit 0;

=head1 FUNCTIONS

=head2 push_to_mongodb

 pushes the rules to a mongodb

=cut

sub push_to_mongodb {
  our $conn;

  my $sids  = shift;
  my $total = 0;
  my $new   = 0;
  my $db    = $conn->rules;
  my $dbr   = $db->$MONGOTBL;
  
  foreach my $sid (keys (%$sids)) {
    my $match = 0;
    next if $sid == 0;
    $total++;
    my $s = $rules->{$GID}->{$sid};
  
    my $cnt = $dbr->count({ sid => "$s->{'sid'}" });
  
    if ( $cnt > 0 ) {
      print "[I] Found $cnt rules with the same sid:". $s->{'sid'} ."\n" if $VERBOSE;
      #next;
    }
  
    my $cur = $dbr->find({ sid => "$s->{'sid'}" });
  
    while (my $doc = $cur->next) {
      # $doc->{'gsrmd5'} eq $s->{'gsrmd5'}
      if ( $doc->{'rmd5'} eq $s->{'rmd5'} ) {
        if ( $doc->{'gsrmd5'} eq $s->{'gsrmd5'} ) {
          print "[*] Rule entry exists: ". $doc->{'gid'} .":". $doc->{'sid'} .":". $doc->{'rev'} ." - Skipping!\n" if $VERBOSE;
          $match = 1;
        }
      } elsif ( $doc->{'gsrmd5'} eq $s->{'gsrmd5'} ) {
          print "[E] gid:sid:rev is the same, but rule has been changed for: [";
          print $doc->{'gid'} .":". $doc->{'sid'} .":". $doc->{'rev'} ."]\n";
          print "[I] Did you forget to increment the revision number maybe?\n";
          exit 1;
          $match = 1;
      }
    }
  
    if ( $match == 0 ) {
      $new++;
      print "[*] Adding new Rule: [" . $s->{'gid'} .":". $s->{'sid'} .":". $s->{'rev'} ."] $s->{'msg'}\n";
      $dbr->insert({ "gid"      => $s->{'gid'},
                     "sid"      => $s->{'sid'},
                     "rev"      => $s->{'rev'},
                     "gsrmd5"   => $s->{'gsrmd5'},
                     "rmd5"     => $s->{'rmd5'},
                     "rgrp"     => $s->{'rulegroup'},
                     "enabled"  => $s->{'enabled'},
                     "action"   => $s->{'action'},
                     "proto"    => $s->{'proto'},
                     "sip"      => $s->{'sip'},
                     "sport"    => $s->{'sport'},
                     "dir"      => $s->{'dir'},
                     "dip"      => $s->{'dip'},
                     "dport"    => $s->{'dport'},
                     "msg"      => $s->{'msg'},
                     "options"  => $s->{'options'},
                     "tlp"      => $s->{'tlp'},
                     "author"   => $s->{'author'},
                     "dengine"  => $s->{'dengine'},
                     "type"     => $s->{'type'},
                     "killchain"=> $s->{'killchain'},
                     "intset"   => $s->{'intrusionset'},
                     "cdate"    => $s->{'date_created'},
                     "mdate"    => $s->{'date_modified'},
                    });
    }
  }
  
  print "[*] Processed $total rules and added $new new to MongoDB backend.\n";
}

=head2 update_current_rules_mongodb

 Updates a mongodb table with the current sids, and the highest revision.
 This list can be used for extracting the latest ruleset.

=cut

sub update_current_rules_mongodb {
  our $conn;
  my $db  = $conn->rules;
  
  my $map = <<MAP;
  function() {
    emit(this.sid, this.rev);
  };
MAP
  
  my $reduce = <<REDUCE;
  function(SID, REVs) {
    var reducedObject = {
      sid: SID,
      rev: 1
    };
    reducedObject.rev = Math.max.apply( Math, REVs );
    return reducedObject;
  };
REDUCE
 
  my $cmd = Tie::IxHash->new("mapreduce" => $MONGOTBL,
                             "map"       => $map,
                             "reduce"    => $reduce,
                             "query"     => {
                                              sid => {
                                                       '$exists' => 1
                                                     },
                                              rev => {
                                                       '$exists' => 1
                                                     }
                                            },
                             "out"       => $MONGOTBL_C
                            );
  
  print "[*] Updating current rules...\n";
  my $res = $db->run_command($cmd);
  #print Dumper $res;
  if ($res->{ok} == 1) {
    print "[*] Status: Ok";
  } else {
    print "[E] Status: Error!";
  }
  print " (". $res->{timeMillis} ."ms)\n";
}

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
        exit 1;
    }
    foreach my $FILE ( @FILES ) {
       $NRULEDB = get_rules ("$RULESDIR/$FILE",$NRULEDB,$VERBOSE,$DEBUG);
       if ( $NRULEDB->{1}->{0}->{'OK'} == 0 ) {
          print "[E] Error when parsing $RULESDIR$FILE: $!\n";
          exit 1;
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
        exit 1;
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

  return $rf if not ( $rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/);
  ($rf->{'action'}, $rf->{'proto'}, $rf->{'sip'}, $rf->{'sport'}, $rf->{'dir'}, $rf->{'dip'}, $rf->{'dport'}, $rf->{'options'}) = ($1, $2, $3, $4, $5, $6, $7, $8);

  #$rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/;
  #my ($action, $proto, $sip, $sport, $dir, $dip, $dport, $options) = ($1, $2, $3, $4, $5, $6, $7, $8);

  unless($rule) {
    print "[E] Error: Not a valid rule in: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  if (not defined $rf->{'options'}) {
    print "[E] Error: Options missing in rule: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  # ET rules has: "sid: 2003451;"
  unless( $rf->{'options'} =~ /sid:\s*([0-9]+)\s*;/ ) {
    print "[E] No sid found in rule options: '$RFILE'\n";
    print "[D] RULE: $rf->{'options'}\n" if $DEBUG;
    exit 1;
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
    print "[E] Rule optionorder inconsistency: '$RFILE'\n";
    print "[D] Should be: (msg:.*metadata:.*classtype:.*sid:.*rev:)\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  # Check some other personal preferences for consistency
  # "(content|dsize|flowint|flowbits|stream_size|reference|metadata):"
  if ( $rf->{'options'} =~ /flow:\s*([\w,]+)\s*;/ ) {
    my $flow = $1;
    if ( $flow =~ /(from_server|from_client)/ ) {
      print "[E] flow option inconsistency (use to_server/to_client): $flow '$RFILE'\n";
      print "[D] RULE: $rule\n" if $DEBUG;
      exit 1;
      return $rf;
    }
    if ( $flow =~ /_(server|client).*(established|stateless)/ ) {
      print "[E] flow option inconsistency (use state before direction): $flow '$RFILE'\n";
      print "[D] RULE: $rule\n" if $DEBUG;
      exit 1;
      return $rf;
    }
  }

  # Error if we see common cases of missing space, like ";keyword:" 
  if ( $rf->{'options'} =~ /;(msg|flow|content|dsize|flowint|flowbits|stream_size|reference|metadata|sid|rev):/ ) {
    print "[E] Possible missing space between keyword ($1) and option. '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
  }

  # Error if we see common cases of extra space, like "keyword: option" 
  if ( $rf->{'options'} =~ /(msg|flow|content|dsize|flowint|flowbits|stream_size|reference|metadata|sid|rev): / ) {
    print "[E] Possible extra space between keyword ($1) and option. '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
  }

  # My way of writing metadata should be there, else fail!
  unless ( $rf->{'options'} =~ / metadata:\s*(.*)\s*; classtype:/ ) {
    print "[E] Metadata missing/b0rked in rule: '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }
  $rf->{'metadata'} = $1;

  # Now pick the metadata appart!
  # author acronyme-user, dengine snort-2.9.4, tlp white, type banker, killchain c2, intrusionset poetlovers, date_created 2013-01-01, date_modified 2013-01-12
  unless ( $rf->{'metadata'} =~ /^author (.+), dengine (.+), tlp (.+), type (.+), killchain (.+), intrusionset (.+), enabled (.+), date_created (.+), date_modified (.+)$/ ) {
    print "[E] Metadata b0rked in rule: '$RFILE'\n";
    print "[D] RULE: $rf->{'metadata'}\n" if $DEBUG;
    exit 1;
    return $rf;
  }
  ($rf->{'author'}, $rf->{'dengine'}, $rf->{'tlp'}, $rf->{'type'}, $rf->{'killchain'}, $rf->{'intrusionset'}, $rf->{'enabled'}, $rf->{'date_created'}, $rf->{'date_modified'})
      = ($1, $2, $3, $4, $5, $6, $7, $8, $9);

  # Strip out the metadata from the original option!
  $rf->{'options'} =~ s/metadata:\s*author (.+), dengine (.+), tlp (.+), type (.+), killchain (.+), intrusionset (.+), enabled (.+), date_created \d\d\d\d-\d\d-\d\d, date_modified \d\d\d\d-\d\d-\d\d\s*; //;

  # Check for valid TLP color :)
  unless ( $rf->{'tlp'} =~ /^(white|green|amber|red)$/ ) {
    print "[E] Invalid TLP: $rf->{'tlp'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  # Check for more or less valid dengine
  unless ( $rf->{'dengine'} =~ /^((snort|suricata)-(\d\.\d{1,2}(\.\d{1,2})?))$/ ) {
    print "[E] Invalid dengine: $rf->{'dengine'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  # Check for valid KillChain state
  unless ( $rf->{'killchain'} =~ /^(reconnaissance|weaponization|delivery|exploitation|installation|c2|actions|none)$/ ) {
    print "[E] Invalid killchain entry: $rf->{'killchain'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  unless ( $rf->{'date_created'} =~ /^\d\d\d\d-\d\d-\d\d$/ ) {
    print "[E] Invalid date_created: $rf->{'date_created'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  unless ( $rf->{'date_modified'} =~ /^\d\d\d\d-\d\d-\d\d$/ ) {
    print "[E] Invalid date_modified: $rf->{'date_created'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  unless ( $rf->{'enabled'} =~ /^(yes|no)$/ ) {
    print "[E] Invalid state for enabled: $rf->{'enabled'} in '$RFILE'\n";
    print "[D] RULE: $rule\n" if $DEBUG;
    exit 1;
    return $rf;
  }

  $rf->{'gsrmd5'} = md5_hex("$GID:$rf->{'sid'}:$rf->{'rev'}");
  $rf->{'rmd5'}   = md5_hex("$rule");
  $rf->{'gid'}    = $GID;

  $rf->{OK} = 1;
  return $rf;
}

