<pre>
#
#  ______ ______ ______  ______    
# /\  ___/\  ___/\  ___\/\  ___\   
# \ \  __\ \  __\ \___  \ \___  \  
#  \ \_\  \ \_\  \/\_____\/\_____\ 
#   \/_/   \/_/   \/_____/\/_____/ 
#                                
# - A Framework For Sid Sharing
#
</pre>

Framework For Sid Sharing (FFSS)
================================

FFSS is a `suggestion` for a more standard way to write Snort/Suricata/... rules.
It aims to help people and teams who write rules, to write them consistently, and
to help share rules with others that writes and shares rules in the same way.

FFSS consists of a set of scripts that will help keep rulewriters within a set of
policies for how to write rules. The setup is focused on writing your rules in 
textfiles, and using git for version control. The git-server will also have some
hooks set up, so that the final ruleset will be in a mongodb, ready to be fetched
to compile a ruleset for the current valid rules.

The framework will also help a team so there will never be a sid collition, and
if someone changes a rule, the backend will notice and not update it if you forget
to up the revision etc.

Flame and suggestion for making it better is welcome!
