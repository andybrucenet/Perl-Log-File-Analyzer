#!/usr/bin/perl

#######################################################################
# logengine.pl, ABr, 5/30/01
#
# Engine that allows us to analyze any log file for patterns, and then
# to take actions based on the patterns.
#
# This code is copyrighted by Andy Bruce ("the author"). It is freely
# available for use in any application, but the source code must be
# released as-is. No warranty, either express or implied, is provided
# with this code. No implied warranty, nor implication of fitness for
# use or purpose, is provided with this code. This code is provided to
# the computing community in the hope that it will be useful. While the
# author is interested in hearing of defects or suggested improvements,
# the author makes no provision or promise to implement any suggestions
# or corrections.

use strict ;

require "debug.pl" ;
require "os.pl" ;
require "paths.pl" ;
require "utils.pl" ;

#######################################################################
# STRUCTURES
#
# A handy structure for holding name/value pairs. Used all over the
# place in this script.
# NAMEVALUEOBJ:
#   NAME => name of the object
#   VALUE => value associated with the object
#
# A handy structure is the "hash-array". A hash-array allows you to 
# store an item indexed by a key (for fast lookups) as well as an
# array (to maintain original order).
# HASHARRAY:
#   ARRAY => array entries
#   HASH => hash entries
#
# Handy structure for the log files we open and process.
# LOGFILE:
#   NAME => file name
#   KEEP_OPEN => should this file continue to be read forever?
#   HANDLE => the open file handle for this file
#   LINENO => current line number
#
# This script can read any number of rule scripts. When we parse the
# command line, we store each rule script to read as one of these.
# RULESCRIPT:
#   NAME => file name
#   RULES => rules specific to this script
#   PROCESSED => has this script file been processed?
#
# The RULEVAR structure defines a NAME/VALUE pair with an additional
# "PAREN" field. The PAREN field gives the numeric index of the match
# that we need to extract if the variable is a run-time variable.
# RULEVAR:
#   NAME => name of the variable
#   VALUE => for compile-time fields, always set. for run-time
#     vars, determined at run-time
#   PAREN => see above
#   IS_ARRAY => true if this is an ARRAY variable
#   IS_RUNTIME => true if this is a runtime variable
#
# The RUNTIMEEXTRACT structure defines the meta-data necessary to
# bind information from one variable to another variable at runtime.
# A specific example:
#  BEGIN = $$RUNTIME_DATA([0-9]+)
#  BEGIN = $RUNTIME_DATA
# In this example, the first BEGIN defines a variable called
# RUNTIME_DATA. The value of this variable is known only after a
# match is made (in this case, reading a line with one or more
# numerics in it). The second BEGIN gets $RUNTIME_DATA replaced
# *at run-time* with the value retrieved from the first match.
# Assume two input lines like the following:
#  "Hello, World! 12345 is the number!"
#   "For the second line, 12345 is what we have!"
# We process the first line. It matches the first BEGIN. Because
# the first BEGIN specifies a run-time variable, we take the
# appropriate data ("12345", the numeric) and save it into
# RUNTIME_DATA.
# Then we process the second line. Because the first BEGIN
# already matched, we check the second line against the second
# BEGIN. Before we do the regex, we replace the reference to
# RUNTIME_DATA with the value we retrieved from the first line.
# Thus, the second BEGIN becomes simply:
#  BEGIN = 12345
# The second line matches, because the pattern "12345" occurs in
# it.
#
# RUNTIMEEXTRACT:
#   VARNAME => name of the variable to bind to
#   MATCH_IDX => number of the match, as in "$1" or "$2" in a
#     straight Perl program
#   IS_ARRAY => true if this variable is an array
#
# The RUNTIMEINSERT structure is the inverse of the RUNTIMEEXTRACT
# structure. For a particular match item, it may be necessary to
# insert a data value extracted by a different match in the same
# rule. In this case, we need to know the character position
# where the insertion should occur.
# RUNTIMEINSERT:
#   VARNAME => name of the variable to bind from
#   CHAR_POS => index where the data should be inserted
#   LENGTH => length of the item to replace in the string
#
# A compiled regex (for speed; we can precompile if no run-time
# vars are specified in the regex).
# COMPILED_SUB:
#   SRC_CODE => source code to be compiled
#   COMPILED_CODE => compiled source code
#
# CACHEMATCH: This structure exists to *speed up* rule processing.
# Basically, if we detect that a regular expression is being executed
# twice, we save off the results from the first comparison.
# CACHEMATCH:
#   REGEX => regex expression
#   NUM_REGEXES => number of regexes for all rules that use this cache
#   LAST_LINEID => last ID for which we have a match
#   RESULTS => array of matched items from last regex
#   NUM_MATCHES => number of matches made through this cache item
#   COMPILED_SUB => COMPILED_SUB object
#
# The BEGIN/END match data associated with a rule has the following
# structure. Keep in mind that RUNTIME_VARS are basically deferred
# macros that get replaced just prior to doing a regex on a particular
# match item.
# MATCHDATA:
#   ORIG_VALUE => unexpanded, original value
#   REGEX_OPTIONS => regex options
#   VALUE => expanded value (including all macros)
#   RUNTIME_INSERT => array of RUNTIMEINSERT entries
#   RUNTIME_EXTRACT => array of RUNTIMEEXTRACT entries
#   IS_PRE => is this a "pre" match?
#   IS_BEGIN => is this a "BEGIN" match?
#   IS_END => is this an "END" match?
#   IS_ACCUM => flag if this is an "accumulation"
#   IS_CODE => does this match actually refer to code or a regex?
#   MATCH_TIMEOUT => # lines within which this match must occur
#   CACHEMATCH => if set, then this is the reference to the cached regex
#   COMPILED_SUB => if IS_CODE true, then this is the compiled routine
#  
# ACTIONOBJ defines a single action object
#   NAME => name of the action
#   VALUE => source code to execute
#   CODE => compiled code (created after first execution)
#
# The RULE structure defines a single atomic rule that we can process
# RULEOBJ:
#   NAME => name of the rule
#   FULLNAME => fully-qualified rule name (for script context)
#   IS_MACRO => is this a "real" rule or simply a macro?
#   ENABLED => is this rule to be processed or not?
#   SCRIPT => RULESCRIPT object that we read this rule from
#   STARTLINE => beginning line for this rule from the script
#   STOPLINE => ending line for this rule from the script
#   ACTION => hash of ACTIONOBJ actions for this rule
#   PRE_MATCH => array of MATCHDATA entries
#   BEGIN_MATCH => array of MATCHDATA entries
#   OPTIONAL_MATCH => array of MATCHDATA entries
#   END_MATCH => array of MATCHDATA entries
#   MATCHES => array of MATCHDATA entries, in order
#   VARS => hash of RULEVAR entries associated with this rule
#   FOUND => set to non-zero if this rule ever got executed
#   RULE_TIMEOUT => if no matches in this # of lines, destroy instance
#
# The RULEINST structure defines a *potential* match for a rule as we
# scan through the log file(s).
# RULEINST:
#   FIRST_TIME => flag
#   RULE => pointer back to rule
#   AR_INDEX => array index in global variable
#   HASH_INDEX => array index of this instance in global hash
#   MATCH_IDX => index number of current match
#   MATCH_CNT => number of array entries (for quick reference)
#   STARTLINE => line number where the match begin
#   STOPLINE => line number where the match ended
#   RTVARS => hash of RUNTIMEVARS
#   LAST_MATCH_LINE => line # of the last match (for timeout)
#   RULES_CREATED => hash of rule names created from this rule
#   LOGFILE => LOGFILE structure where the first match occurred
#
# The RUNTIMEVAR structure allows us to store extracted run-time
# data separately for each rule instance.
# RUNTIMEVAR:
#   RULEINST => instance of the rule
#   RULEVAR => RULEVAR entry from the rule vars hash
#   VALUE => actual value extracted at run-time

#######################################################################
# GLOBALS
my $gRC_SUCCESS = 0 ;            # no error
my $gRC_HELP = 1 ;               # help requested
my $gRC_CMD_LINE_SWITCH = 2 ;    # invalid switch passed
my $gRC_CMD_LINE_INTERNAL = 3 ;  # internal cmd line parse err
my $gRC_CMD_LINE_ARGS = 4 ;      # error with cmd line args
my $gRC_NO_SCRIPTS = 5 ;         # no scripts specified
my $gRC_SCRIPT = 6 ;             # general error in script
my $gRC_ERROR = 7 ;              # general purpose error

# for sorting logfile names read from disk
my $gSORT_NONE = 0 ;
my $gSORT_ASC = 1 ;
my $gSORT_DESC = 2 ;

my $gFOREVER = 0 ;            # read next log file forever?
my $gSORT = $gSORT_NONE ;     # sort logfile names from disk?
my $gDUMP = 0 ;               # dump the loaded file?
my $gSTATUS = 0 ;             # show status as we process?
my $gSTUDY = 0 ;              # should we study lines?
my $gBUFFER = 0 ;             # should we use buffered i/o?
my $gFAST = 1 ;               # fast simple rule processing?
my $gMAN = 0 ;                # show add'l usage notes?

my $gPrintedTitle = 0 ;       # only print the title once
my $gPrintedUsage = 0 ;       # only print the help once

my %gUserOptions ;            # user options from cmd line
my %gUserOptionsUsed ;        # helper to save ref'ed options

# the list of shared code variables. each one is eval'ed at the
# global scope.
my @gSharedCode ;

# the list of termination code variables; gets run at program end
my @gTerminationCode ;

# this is the list of all loaded rules for all scripts
my $gRules = {
  ARRAY => [],
  HASH => {},
} ;

# this is the list of rules that we need to process as we read each
# line from the log file(s). it's a subset of the gRules above
my @gRulesToProcess ;

# this is the actual set of currently active rule instances. the
# hash is a hash of rule instance arrays, which allows me to
# support multiple concurrent instances of a rule. the array is
# simply an array of rule instances.
my %gRuleInstances ;
my @gRuleInstances ;
my $gInstanceIndex = 0 ;
my $gNumInstances = 0 ;
my $gRuleTimeoutDefault = 15000 ;
my $gMatchTimeoutDefault = 0 ;

# we save the last occurrence of each instance as it fires.
my %gRulePrevInstances ;
my $gRuleInstCurrent ;
my @gWinningRulesForInstanceCreation ;

# the last set of matches from a regex
my @gMatches ;

my @gScripts ;              # rule scripts from cmd line
my %gScripts ;              # hash of the scripts
my @gLogFiles ;             # log files to process
my $gLogFile ;              # current log file entry processed

# allowed actions
my $gActionTypes =
  "CREATE COMPLETE DESTROY TIMEOUT " .
  "MATCH_TIMEOUT MISSING INCOMPLETE" ;

# buffer for output
my %gBuffers ;

# should logengine continue processing?
my $gLogengineQuitFlag = 0 ;

# CACHEMATCH buffer and data
my @gCacheMatches ;            # array of CACHEMATCH items

# line last read (available to scripts)
my $LINE_ID ;              # unique number for each line read
my $LINE_LASTREAD = "" ;

# set some variables available for the scripts
my $LINENUMBER_CURRENT = 0 ;
my $LINENUMBER_START = 0 ;
my $LINENUMBER_STOP = 0 ;
my $LINENUMBER_RANGE = "0,0" ;

# handy file access options (for optimized file i/o)
my $gFILE_OPENMODE_SIMPLE = -1 ;
my $gFILE_OPENMODE_NORMAL = 0 ;
my $gFILE_OPENMODE_INTERNAL_BUFFER = 1 ;

my $gFILE_MODE_INPUT = 0 ;
my $gFILE_MODE_OUTPUT = 1 ;
my $gFILE_MODE_APPEND = 2 ;

my $gFileMode = $gFILE_OPENMODE_NORMAL ;

#######################################################################
# a little different here; usually I do "exit( main() ) ;" here. 
# however, i want the user to have the ability to define variables and
# so on at the global level.

# initialize
my $rc = init() ;
exit( $rc ) if( $gRC_SUCCESS != $rc ) ;

# first, we pre-declare global macros
my $macros = "" ;
my $rule ;
foreach $rule (@{$gRules->{ARRAY}}) {
  if( $rule->{IS_MACRO} ) {
    # a macro is a pseudo-rule with no actions
    my $arBeginMatch = $rule->{BEGIN_MATCH} ;
    my $match = ${$arBeginMatch}[0] ;
    my $newResult = {
      EXPANDED => "",
      ERROR => "",
      RESOLVED_ITEMS => {},
      OPEN_PARENS => 0,
      RUNTIME => 0,
      IDX => 0,
    } ;
    my $rc = resolveExpandItem(
      $rule, 'BEGIN_MATCH', 0, $match, $newResult ) ;
    my $expanded = $newResult->{EXPANDED} ;
    $expanded =~ s/\$$/\\\$/ ;

    # add to our list
    $macros .= " " if( length( $macros ) ) ;
    $macros .= "\$$rule->{NAME}=\"$expanded\" ;" ;
  } #if
} #foreach
ABR::verboseprint( "Executing user-defined macros: '$macros'\n" ) ;
no strict ;
$macros =~ s/(\\)/\\$1/g ;
#print "macros='$macros'\n" ;
eval "$macros" ;
my $result = $@ ;
use strict ;
if( length( $result ) ) {
  print "Macro Definition failure: '$result'\n" ;
} #if

# we now use this opportunity to declare any user variables at the
# global level.
my $sharedCode = "" ;
my $codeEntry ;
foreach $codeEntry (@gSharedCode) {
  my $code = $codeEntry->{VALUE} ;
  ABR::verboseprint( "Executing user-defined shared-code: '$sharedCode'\n" ) ;
  no strict ;
  eval "$code" ;
  my $result = $@ ;
  use strict ;
  if( length( $result ) ) {
    print "Shared Code '$codeEntry->{NAME}' failure: '$result'\n" ;
    print " Code: '$code'\n" ;
  } #if
} #foreach

# now, we ensure that every user-defined option passed on the command
# line was referenced
my $key ;
my $userOptError = 0 ;
foreach $key (sort( keys( %gUserOptions ) )) {
  if( !$gUserOptionsUsed{$key} ) {
    title() ;
    $userOptError = 1 ;
    print "Error: unreferenced user option '$key'\n" ;
  } #if
} #foreach
if( $userOptError ) {
  print "\n" ;
  usage() ;
  exit( $gRC_CMD_LINE_SWITCH ) ;
} #if

# if successful init, run program
if( !$rc ) {
  $rc = run() ;

  # terminate the program
  my $donerc = done( $rc ) ;

  # if we didn't have an error from above, use the return code
  # from the termination routine
  $rc = $donerc if( !$rc ) ;
} #if

# the final result
exit( $rc ) ;

#######################################################################
# PROGRAM IMPLEMENTATION

############################################################
# utilities
sub title {
  return if( $gPrintedTitle ) ;
  $gPrintedTitle = 1 ;

  print "$0, v1.0\n" ;
  print "Copyright (c) 2001-2005 Andy Bruce\n" ;
  print "\n" ;
  print "With optimized caching, pre-compiled regex,\n" ;
  print "and multi-state match support\n" ;
  print "\n" ;
} #title

############################################################
# display usage screen
sub usage {
  return if( $gPrintedUsage ) ;
  $gPrintedUsage = 1 ;

  title() ;
  print "Usage:\n" ;
  print "  $0 -r(ules) <rules-script-name>\n" ;
  print "    -stdin -(no)forever -sort <asc/desc/none>\n" ;
  print "    -log(file) <logfile-spec> -status <lines>\n" ;
  print "    -study <length> -user \"name=value ...\"\n" ;
  print "    -buffer <KB to buffer> -title -version -verbose -debug -?\n" ;
  print "Options:\n" ;
  print "  -rules   - Can be repeated for multiple scripts\n" ;
  print "  -stdin   - Read rules from stdin\n" ;
  print "  -forever - indicates the next log file should be read forever\n" ;
  print "  -sort    - sorts the next log file names read from disk\n" ;
  print "  -logfile - Can be repeated to process multiple logs\n" ;
  print "  -status  - display info on files as we process them\n" ;
  print "  -(no)fast    - optimizes rules processing for simple rules\n" ;
  print "  -study   - tweak that *may* speed up processing\n" ;
  print "  -user    - allows you to pass cmd line args to rules scripts\n" ;
  print "  -buffer  - use buffered I/O\n" ;
  print "  -title   - force the title to print\n" ;
  print "  -version - prints only version information\n" ;
  print "  -verbose - verbose mode--prints detailed load information\n" ;
  print "  -debug   - debug mode--prints numerous messages\n" ;
  print "  -dump    - print loaded script file and exit\n" ;
  print "  -?       - prints this usage screen (also -help or -usage)\n" ;
  print "  -man     - prints usage screen with many notes\n" ;
  if( $gMAN ) {
    print "\n" ;
    print "MANUAL PAGE NOTES:\n" ;
    print "  -buffer\n" ;
    print "    This switch allows the caller to indicate how big the\n" ;
    print "    internal buffer used to read data files should be. The\n" ;
    print "    default value is 16 (16,384 bytes). Many tests show that\n" ;
    print "    this default provides the best program performance. Use a\n" ;
    print "    value of zero to use the native I/O buffering provided by\n" ;
    print "    Perl.\n" ;
    print "\n" ;
    print "  -fast\n" ;
    print "    This switch is turned ON by default, which means that\n" ;
    print "    *simple* rule matches don't fire the CREATE or DESTROY\n" ;
    print "    actions. Only the COMPLETE action gets fired. This greatly\n" ;
    print "    improves the program's performance, but gives the rule\n" ;
    print "    definer less notifications.\n" ;
    print "\n" ;
    print "    A *simple* rule is one which has only a single BEGIN\n" ;
    print "    statement defined for it. Use '-nofast' to ensure that\n" ;
    print "    CREATE/DESTROY actions get fired for every rule.\n" ;
    print "    Example:\n" ;
    print "      [SIMPLE_RULE]\n" ;
    print "      BEGIN=^Hello, World!\n" ;
    print "      Action.COMPLETE=\"Another match\@\$LINENUMBER_START\\n\"\n" ;
    print "\n" ;
    print "  -forever\n" ;
    print "    Use this switch to indicate that a file should be read\n" ;
    print "    continuously. This allows you to emulate 'tail' function-\n" ;
    print "    ality in the logengine. Use it when you're scanning a file\n" ;
    print "    that's being updated as you scan it.\n" ;
    print "\n" ;
    print "  -sort\n" ;
    print "    When you specify an argument for the -logfile option, you\n" ;
    print "    may specify glob wildcards (e.g. 'mylog.*'). By default,\n" ;
    print "    the logengine loads these files in the order it reads them\n" ;
    print "    from the disk (not necessarily sorted on all OS's). You can\n" ;
    print "    control the sort order by using ASC, DESC, or NONE. Keep in\n" ;
    print "    mind that you can use multiple -logfile options on the command\n" ;
    print "    line; the last -sort option read controls how the next set of\n" ;
    print "    log files gets read from the disk.\n" ;
    print "\n" ;
    print "  -study\n" ;
    print "    This switch submits each line with a length equal to\n" ;
    print "    or greater than the specified value to extra analysis.\n" ;
    print "    This extra analysis rarely improves the overall program\n" ;
    print "    performance, but where speed is of the essence it's worth\n" ;
    print "    investigating this switch with different values. Using a\n" ;
    print "    value of 100 or more generally provides the best results.\n" ;
    print "\n" ;
    print "  -user\n" ;
    print "    This switch allows you to pass cmd line arguments directly\n" ;
    print "    to a loaded rules script. The next argument should always be\n" ;
    print "    wrapped in quotes, and should have the form name=value:\n" ;
    print "      -user \"myoption=myvalue\"\n" ;
    print "    The logengine saves these user variables, and rule scripts\n" ;
    print "    can access them by using the LOGENGINE_GET_USER_OPT function.\n" ;
    print "\n" ;
    print "    The logengine allows you to specify multiple occurrences of\n" ;
    print "    the same option; the LOGENGINE_GET_USER_OPT function returns\n" ;
    print "    an array of all the values that the user specified for an\n" ;
    print "    option on the command line.\n" ;
  } #if
} #usage

############################################################
# display error and exit
sub _errorExit {
  my( $rc, $msg ) = @_ ;
  title() ;
  print "Error: $msg\n" ;
  print "\n" ;
  exit( $rc ) ;
} #_errorExit

############################################################
# display error and usage screen
sub _errorHelp {
  my( $rc, $msg ) = @_ ;
  title() ;
  print "Error: $msg\n" ;
  print "\n" ;
  usage() ;
  return $rc ;
} #_errorHelp

############################################################
# file handle operations
sub fileOpen {
  my( $fname, $openMode, $mode ) = @_ ;

  # open the file
  local( *FILEHANDLE ) ;
  my $error ;
  if( $gFILE_OPENMODE_SIMPLE == $openMode ) {
    return undef if( !open( FILEHANDLE, "$fname" ) ) ;
    return *FILEHANDLE ;
  } elsif( $gFILE_OPENMODE_NORMAL == $openMode ) {
    # open the file using normal perl "open"
    my $_mode = "" ;

    # determine the mode (passed with filename)
    if( $gFILE_MODE_INPUT == $mode ) {
      $_mode = "< " ;
    } elsif( $gFILE_MODE_OUTPUT == $mode ) {
      $_mode = "> " ;
    } elsif( $gFILE_MODE_APPEND == $mode ) {
      $_mode = ">> " ;
    } #if

    # do the open
    return undef if( !open( FILEHANDLE, "$_mode$fname" ) ) ;
  } else {
    my $_mode ;
    no strict ;
    if( $gFILE_MODE_INPUT == $mode ) {
      $_mode = O_RDONLY ;
    } elsif( $gFILE_MODE_OUTPUT == $mode ) {
      $_mode = O_WRONLY ;
    } elsif( $gFILE_MODE_APPEND == $mode ) {
      $_mode = O_APPEND ;
    } #if
    use strict ;
    return undef if( !sysopen( FILEHANDLE, "$fname", $_mode ) ) ;

    # do this so we get proper bytes
    binmode( FILEHANDLE ) ;
  } #if

  # create object for user
  my $handle = {
    HANDLE => *FILEHANDLE,
    OPEN_MODE => $openMode,
    MAX_BUFFER_SIZE => ( $gBUFFER * 1024 ),
    BUFFER => undef,
    OFS => 0,
    LEN => 0,
    BYTES_READ => 0,
    BYTES_WRITTEN => 0,
    ERROR => $error,
  } ;

  return $handle ;
} #fileOpen 

sub fileReady {
  my $handle = shift() ;

  # sanity
  return -1 if( !defined( $handle ) ) ;

  # on Windows, we can't use select
  if( $ABR::gOsIsWindows ) {
    # if the file is open, it's ready to read
    return 1 ;
  } #if

  # on real OSs, we can use select

  # first, construct the bitmask
  my( $rin, $win, $ein ) ;
  $rin = $win = $ein = "" ;
  vec( $rin, fileno( $handle->{HANDLE} ), 1 ) = 1 ;
  $ein = $rin | $win ;

  # now, do the select with no delay (is data ready now?)
  my( $nfound, $timeleft, $rout, $wout, $eout, $timeout ) ;
  ( $nfound, $timeleft ) =
    select( $rout = $rin, $wout = $win, $eout = $ein, 0 ) ;

  # final result
  return $nfound ;
} #fileReady

sub fileReadLine {
  my $handle = shift() ;

  # on Windows, we must simply read what's available
  if( $gFILE_OPENMODE_NORMAL == $handle->{OPEN_MODE} ) {
    my $line ;
    my $fileHandle = $handle->{HANDLE} ;
    chomp( $line = <$fileHandle> ) ;
    $line =~ s/[\n\r]+$// ;
    return $line ;
  } else {
    # do we have anything in our buffer?
    my( $line, $idx, $len ) ;
    while( 1 ) {
      # load buffer if necessary. if we're at the end,
      # then exit the loop.
      if( $handle->{OFS} >= $handle->{LEN} ) {
        # now load data (large chunks)
        $len = sysread( $handle->{HANDLE},
          $handle->{BUFFER}, $handle->{MAX_BUFFER_SIZE} ) ;
        return undef if( !$len ) ;

        # save data
        $handle->{OFS} = 0 ;
        $handle->{LEN} = $len ;
        $handle->{BYTES_READ} += $len ;
      } #if

      # find first 0x0A (line feed)
      $idx = index( $handle->{BUFFER}, chr( 0x0A ),
        $handle->{OFS} ) ;
      
      # if not found, add the *entire* buffer to the
      # line and reloop (handles long lines)
      if( $idx < 0 ) {
        $line .= $handle->{BUFFER} ;
        $handle->{OFS} = $handle->{LEN} ;
        next ;
      } #if

      # append everything to the line, increment the
      # offset
      $len = $idx - $handle->{OFS} ;
      if( $len ) {
        $line .= substr( $handle->{BUFFER},
          $handle->{OFS}, $len ) ;
      } #if
      $handle->{OFS} = $idx + 1 ;

      # get rid of the CR if necessary
      if( length( $line ) ) {
        if( substr( $line, $len - 1 ) eq chr( 0x0D ) ) {
          chop( $line ) ;
        } #if
      } #if

      # exit loop
      if( !defined( $line ) ) {
        # no problems here, just an empty line
        $line = "" ;
      } #if
      return $line ;
    } #while

    # the completed line
    return $line ;
  } #if
} #fileReadLine 

sub fileClose {
  # we get a "pointer" to the file object. this allows
  # us to update the file object itself once we close
  # the file. this allows all file functions to be
  # called on closed objects without errors.
  my $refHandle = shift ;
  return 0 if( !defined( $refHandle ) ) ;
  return 0 if( !defined( $$refHandle ) ) ;
  my $handle = $$refHandle ;
  if( defined( $handle->{HANDLE} ) ) {
    close( $handle->{HANDLE} ) ;
  } #if
  $$refHandle = undef ;
} #fileClose

############################################################
# validate the command line
sub parseCmdLine {
  my $rc = $gRC_SUCCESS ;

  # valid states
  my $stateNone = 0 ;
  my $stateScript = 1 ;
  my $stateLogFile = 2 ;
  my $stateStatus = 3 ;
  my $stateStudy = 4 ;
  my $stateBuffer = 5 ;
  my $stateSort = 6 ;
  my $stateUser = 7 ;
  my $state = $stateNone ;

  my $hasAll = 0 ;

  # iterate over arguments
  my $arg ;
  foreach $arg (@ARGV) {
    if( $state == $stateNone ) {
      # look for each of our options
      if( $arg =~ /^--?vers(ion)?$/i ) {
        # show title/version only; then exit
        title() ;
        exit( $gRC_SUCCESS ) ;
      } elsif( $arg =~ /^--?title$/i ) {
        # show title/version and keep going
        title() ;
      } elsif( $arg =~ /^--?verb(ose)?$/i ) {
        $ABR::gVERBOSE = 1 ;
      } elsif( $arg =~ /^--?d(ebug)?$/i ) {
        $ABR::gDEBUG = 1 ;
      } elsif( $arg =~ /^(--?h(elp)?|--?\?|--?u(sage)?)$/ ) {
        usage() ;
        return $gRC_HELP ;
      } elsif( $arg =~ /^--?man$/i ) {
        $gMAN = 1 ;
        usage() ;
        return $gRC_HELP ;
      } elsif( $arg =~ /^--?r(ules)?$/i ) {
        # next arg should be a rules script
        $state = $stateScript ;
      } elsif( $arg =~ /^--?stdin$/i ) {
        # we make an entry
        my $script = {
          NAME => 'STDIN',
          RULES => undef,
        } ;
        push( @gScripts, $script ) ;
        $gScripts{$script->{NAME}} = $script ;
      } elsif( $arg =~ /^--?dump$/i ) {
        $gDUMP = 1 ;
      } elsif( $arg =~ /^--?(no)?forever$/i ) {
        # should next log file be kept open forever?
        if( $arg =~ /noforever/ ) {
          $gFOREVER = 0 ;
        } else {
          $gFOREVER = 1 ;
        } #if
      } elsif( $arg =~ /^--?l(og)?(file)?$/i ) {
        # next arg should be a log file to process
        $state = $stateLogFile ;
      } elsif( $arg =~ /^--?status$/i ) {
        # next arg should be the number lines
        $state = $stateStatus ;
      } elsif( $arg =~ /^--?study$/i ) {
        # next arg should be the length for a study to pop
        $state = $stateStudy ;
      } elsif( $arg =~ /^--?buffer$/i ) {
        # next arg should be the length for a study to pop
        $state = $stateBuffer ;
      } elsif( $arg =~ /^--?sort$/i ) {
        # next arg should be the type of sorting to occur
        $state = $stateSort ;
      } elsif( $arg =~ /^--?user$/i ) {
        # next arg should be the type of sorting to occur
        $state = $stateUser ;
      } elsif( $arg =~ /^--?(no)?fast$/i ) {
        # turn fast processing on/off
        if( $arg =~ /nofast/ ) {
          $gFAST = 0 ;
        } else {
          $gFAST = 1 ;
        } #if
      } else {
        return _errorHelp( $gRC_CMD_LINE_SWITCH, 
          "Invalid switch: $arg" ) ;
      } #if
    } elsif( $stateScript == $state ) {
      my $script = {
        NAME => $arg,
        RULES => undef,
      } ;
      push( @gScripts, $script ) ;
      $gScripts{$script->{NAME}} = $script ;

      $state = $stateNone ;
    } elsif( $stateLogFile == $state ) {
      # update the file name passed
      if( $ABR::gOsIsWindows ) {
        $arg =~ s/\\/\//g ;
      } # if

      # check for STDIN
      my @files ;
      if( $arg ne '-' ) {
        # get the directory
        my $idx = rindex( $arg, "/" ) ;
        my $dir = "." ;
        my $file = $arg ;
        if( $idx > 0 ) {
          $dir = substr( $arg, 0, $idx ) ;
          $file = substr( $arg, $idx + 1 ) ;
        } #if
  
        # load the log files
        @files = ABR::path_readDirSpec( $dir, $file ) ;
        if( !scalar( @files ) ) {
          return _errorHelp( $gRC_CMD_LINE_SWITCH, 
            "Error reading logfile '$arg'" ) ;
        } #if
      } else {
        push( @files, $arg ) ;
      } #if

      # sort appropriately
      SWITCH: {
        ( $gSORT == $gSORT_ASC ) && do {
          @files = sort( @files ) ;
          last SWITCH ;
        } ;

        ( $gSORT == $gSORT_DESC ) && do {
          @files = sort( {$b cmp $a} @files ) ;
          last SWITCH ;
        } ;
      } #SWITCH

      # now create the logfile entries
      my $file ;
      foreach $file (@files) {
        my $logfile = {
          NAME => $file,
          KEEP_OPEN => $gFOREVER,
        } ;
        push( @gLogFiles, $logfile ) ;
      } #foreach

      $state = $stateNone ;
    } elsif( $stateStatus == $state ) {
      $gSTATUS = $arg ;
      if( !( $gSTATUS =~ m/^[0-9]+$/ ) ) {
        return _errorHelp( $gRC_CMD_LINE_SWITCH,
          "\"-status\" requires number of lines" ) ;
      } #if
      $state = $stateNone ;
    } elsif( $stateStudy == $state ) {
      $gSTUDY = $arg ;
      if( !( $gSTUDY =~ m/^[0-9]+$/ ) ) {
        return _errorHelp( $gRC_CMD_LINE_SWITCH,
          "\"-study\" requires number of lines" ) ;
      } #if
      $state = $stateNone ;
    } elsif( $stateBuffer == $state ) {
      $gBUFFER = $arg ;
      if( !( $gBUFFER =~ m/^[0-9]+$/ ) ) {
        return _errorHelp( $gRC_CMD_LINE_SWITCH,
          "\"-buffer\" requires KB to buffer" ) ;
      } #if
      $gFileMode = $gFILE_OPENMODE_INTERNAL_BUFFER ;
      $state = $stateNone ;
    } elsif( $stateSort == $state ) {
      if( $arg =~ m/^asc((end)?ing)?$/i ) {
        $gSORT = $gSORT_ASC ;
      } elsif( $arg =~ m/^desc((end)?ing)?$/i ) {
        $gSORT = $gSORT_DESC ;
      } elsif( $arg =~ m/^none$/i ) {
        $gSORT = $gSORT_NONE ;
      } else {
        return _errorHelp( $gRC_CMD_LINE_SWITCH,
          "\"-sort\" requires none, asc, desc modifier" ) ;
      } #if
      $state = $stateNone ;
    } elsif( $stateUser == $state ) {
      # extract name=value
      my $data = $arg ;
      $data =~ m/^([^=]+)=(.*)$/ ;
      if( !defined( $1 ) || !defined( $2 ) ) {
        return _errorHelp( $gRC_CMD_LINE_SWITCH,
          "\"-user\" requires argument in form \"name=value\"" ) ;
      } #if

      # create array ref if necessary
      my $refAr = $gUserOptions{$1} ;
      if( !defined( $refAr ) ) {
        my @ar ;
        $refAr = \@ar ;
        $gUserOptions{$1} = $refAr ;
      } #if

      # save user option to array
      push( @{$refAr}, $2 ) ;

      $state = $stateNone ;
    } else {
      return _errorHelp( $gRC_CMD_LINE_INTERNAL, 
        "Invalid parse state: $state" ) ;
    } #if
  } #foreach

  # we shouldn't be in a state
  if( $stateNone != $state ) {
    return _errorHelp( $gRC_CMD_LINE_SWITCH,
      "Improperly terminated switch" ) ;
  } #if

  # we must have at least one script file to read
  if( !scalar( @gScripts ) ) {
    return _errorHelp( $gRC_NO_SCRIPTS,
      "Must specify a rules script to read" ) ;
  } #if

  return $rc ;
} #parseCmdLine 

############################################################
# load/compile a script file
sub scriptNewRule {
  my( $name, $state ) = @_ ;

  # we always clear out the RULE pointer since we're in a
  # new section.
  $state->{IN_DEFINE_MACRO} = 0 ;
  $state->{RULE} = undef ;

  # empty section name is invalid. trim the name and test.
  $name =~ s/^\s*(.*?)\s*$/$1/ ;
  if( !length( $name ) ) {
    $state->{ERROR} = "Empty rule name" ;
    return $gRC_SCRIPT ;
  } #if

  # reset rule-specific state info
  $state->{RULE} = undef ;
  $state->{REGEX_OPTIONS} = "" ;
  $state->{IN_DEFINE_MACRO} = 0 ;
  $state->{IN_SHARED_CODE} = 0 ;
  $state->{MATCH_TIMEOUT} = 0 ;
  $state->{MATCH_NEXT_LINE} = 0 ;

  # if we have the special keyword DEFINE_MACRO, then we
  # set our state and return
  $state->{IN_DEFINE_MACRO} = ( $name =~ m/^DEFINE_MACRO$/i ) ;
  return $gRC_SUCCESS if( $state->{IN_DEFINE_MACRO} ) ;

  # if we have the special keyword SHARED_CODE, then we
  # set our state and return
  $state->{IN_SHARED_CODE} = ( $name =~ m/^SHARED_CODE$/i ) ;
  return $gRC_SUCCESS if( $state->{IN_SHARED_CODE} ) ;

  # if we have the special keyword TERMINATION_CODE, then we
  # set our state and return
  $state->{IN_TERMINATION_CODE} = ( $name =~ m/^TERMINATION_CODE$/i ) ;
  return $gRC_SUCCESS if( $state->{IN_TERMINATION_CODE} ) ;

  # get the full, qualified name of the rule. this allows
  # the same rule to be defined in multiple files; each rule
  # is independent.
  #my $fullName = uc( "$state->{FNAME}:$name" ) ;
  my $fullName = uc( "$name" ) ;

  # we are defining a new rule with this section. make sure
  # we don't have a duplicate.
  my $isDupe = exists( ${$gRules->{HASH}}{$fullName} ) ;
  if( $isDupe ) {
    $state->{ERROR} = "Duplicate rule '$name'" ;
    return $gRC_SCRIPT ;
  } #if

  # create a new entry
  my $rule = {
    NAME => $name,
    FULLNAME => $fullName,
    IS_MACRO => 0,
    ENABLED => 1,
    SCRIPT => $state->{SCRIPT},
    STARTLINE => $state->{LINE_NO},
    STOPLINE => $state->{LINE_NO},
    ACTION => undef,
    PRE_MATCH => [],
    BEGIN_MATCH => [],
    OPTIONAL_MATCH => [],
    END_MATCH => [],
    MATCHES => [],
    VARS => {},
    FOUND => 0,
    RULE_TIMEOUT => $gRuleTimeoutDefault,
  } ;

  # add it to the array and to the hash
  ${$gRules->{HASH}}{$fullName} = $rule ;
  push( @{$gRules->{ARRAY}}, $rule ) ;

  # save in the state bucket
  $state->{RULE} = $rule ;

  return $gRC_SUCCESS ;
} #scriptNewRule 

sub scriptResetStateMatchNextLine {
  my $state = shift() ;

  if( $state->{MATCH_NEXT_LINE} ) {
    $state->{MATCH_NEXT_LINE} = 0 ;
    $state->{MATCH_TIMEOUT} = 0 ;
  } #if
} #scriptResetStateMatchNextLine 

sub scriptCreateCompiledMatch {
  my( $state, $rvalue, $match ) = @_ ;

  # anything to do?
  return $gRC_SUCCESS if( !$match->{IS_CODE} ) ;

  # create an anonymous routine for the code to execute in
  my $src = "sub {\n" .
    "\t$rvalue\n" .
    "}" ;
  my $code = eval( $src ) ;
  if( !defined( $code ) ) {
    $state->{ERROR} = "CODE '$rvalue' failed compilation: $!" ;
    return $gRC_SCRIPT ;
  } #if

  # update match
  my $compiled_sub = {
    SRC_CODE => $src,
    COMPILED_CODE => $code,
  } ;
  $match->{COMPILED_SUB} = $compiled_sub ;
  return $gRC_SUCCESS ;
} #scriptCreateCompiledMatch 

sub scriptDecodeMacro {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # this is a special case. we create a pseudo-rule
  # for this macro. the only thing the rule has is
  # its name and a single BEGIN match.
  #my $fullName = uc( "$state->{FNAME}:$lvalue" ) ;
  my $fullName = uc( "$lvalue" ) ;

  # it must be unique
  my $isDupe = exists( ${$gRules->{HASH}}{$fullName} ) ;
  if( $isDupe ) {
    $state->{ERROR} = "Duplicate macro '$lvalue'" ;
    return $gRC_SCRIPT ;
  } #if

  # create the pseudo-rule
  my $rule = {
    NAME => $lvalue,
    FULLNAME => $fullName,
    IS_MACRO => 1,
    ENABLED => 0,
    SCRIPT => $state->{SCRIPT},
    STARTLINE => $state->{LINE_NO},
    STOPLINE => $state->{LINE_NO},
    ACTION => undef,
    PRE_MATCH => [],
    BEGIN_MATCH => [],
    OPTIONAL_MATCH => [],
    END_MATCH => [],
    MATCHES => [],
    VARS => {},
    FOUND => 0,
    RULE_TIMEOUT => 0,
  } ;

  # we create the entry and add to the array
  my $beginObj = {
    ORIG_VALUE => $rvalue,
    REGEX_OPTIONS => "",
    VALUE => $rvalue,
    RUNTIME_INSERT => [],
    RUNTIME_EXTRACT => [],
  } ;
  push( @{$rule->{BEGIN_MATCH}}, $beginObj ) ;

  # add it to the array and to the hash
  ${$gRules->{HASH}}{$fullName} = $rule ;
  push( @{$gRules->{ARRAY}}, $rule ) ;

  return $gRC_SUCCESS ;
} #scriptDecodeMacro 

sub scriptDecodeAction {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # user must provide action type
  my $okFormat = ( $lvalue =~ m/^ACTION\.([0-9A-Za-z_]+)/i ) ;
  $okFormat = length( $1 ) if( $okFormat ) ;
  if( !$okFormat ) {
    $state->{ERROR} = "'$lvalue' must be in form ACTION.<action_type>" ;
    return $gRC_SCRIPT ;
  } #if
  my $actionTypeIn = $1 ;

  # must be one of our allowed types
  my $actionType ;
  my $found = 0 ;
  foreach $actionType (split( / /, $gActionTypes )) {
    $found = ( $actionTypeIn =~ m/^$actionType$/i ) ;
    last if( $found ) ;
  } #foreach
  if( !$found ) {
    $state->{ERROR} = "'$actionTypeIn' must be one of $gActionTypes" ;
    return $gRC_SCRIPT ;
  } #if
  $actionType = uc( $actionTypeIn ) ;

  # deref the action data
  my $rule = $state->{RULE} ;
  my $actionObj = $rule->{ACTION} ;
  if( !defined( $actionObj ) ) {
    # first-time logic
    $actionObj = {} ;
    $rule->{ACTION} = $actionObj ;
  } #if

  # it's a valid action. make sure it's the only one
  if( exists( ${$actionObj}{$actionType} ) ) {
    $state->{ERROR} = "Action '$actionType' already exists for rule " .
      "'$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if

  # save the action
  my $actionEntry = {
    NAME => $actionTypeIn,
    VALUE => $rvalue,
  } ;
  ${$actionObj}{$actionType} = $actionEntry ;

  return $gRC_SUCCESS ;
} #scriptDecodeAction 

sub scriptDecodeEnabled {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # rvalue must be boolean
  my $rule = $state->{RULE} ;
  $rule->{ENABLED} = ABR::utils_isTrue( $rvalue ) ;

  return $gRC_SUCCESS ;
} #scriptDecodeEnabled 

sub scriptDecodePre {
  my( $lvalue, $rvalue, $state, $isAccum, $isCode ) = @_ ;

  # simply add the rvalue
  my $rule = $state->{RULE} ;
  my $match = {
    ORIG_VALUE => $rvalue,
    REGEX_OPTIONS => $state->{REGEX_OPTIONS},
    VALUE => $rvalue,
    RUNTIME_INSERT => [],
    RUNTIME_EXTRACT => [],
    IS_PRE => 1,
    IS_BEGIN => 0,
    IS_END => 0,
    IS_ACCUM => length( $isAccum ),
    IS_CODE => length( $isCode ),
    MATCH_TIMEOUT => $state->{MATCH_TIMEOUT},
    CACHEMATCH => undef,
    COMPILED_SUB => undef,

  } ;
  scriptResetStateMatchNextLine( $state ) ;
  my $rc = scriptCreateCompiledMatch( $state, $rvalue, $match ) ;
  return $rc if( $gRC_SUCCESS != $rc ) ;
  
  # check for ACCUM error
  my $isError =
    ( $match->{IS_ACCUM} && !scalar( @{$rule->{PRE_MATCH}} ) ) ;
  if( $isError ) {
    $state->{ERROR} = "ACCUM not valid for first instance of match " .
      "'$lvalue' for rule '$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if

  # add to both arrays
  push( @{$rule->{MATCHES}}, $match ) ;
  push( @{$rule->{PRE_MATCH}}, $match ) ;
  return $gRC_SUCCESS ;
} #scriptDecodePre 

sub scriptDecodeBegin {
  my( $lvalue, $rvalue, $state, $isAccum, $isCode ) = @_ ;

  # simply add the rvalue
  my $rule = $state->{RULE} ;
  my $match = {
    ORIG_VALUE => $rvalue,
    REGEX_OPTIONS => $state->{REGEX_OPTIONS},
    VALUE => $rvalue,
    RUNTIME_INSERT => [],
    RUNTIME_EXTRACT => [],
    IS_PRE => 0,
    IS_BEGIN => 1,
    IS_END => 0,
    IS_ACCUM => length( $isAccum ),
    IS_CODE => length( $isCode ),
    MATCH_TIMEOUT => $state->{MATCH_TIMEOUT},
    CACHEMATCH => undef,
    COMPILED_SUB => undef,
  } ;
  scriptResetStateMatchNextLine( $state ) ;
  my $rc = scriptCreateCompiledMatch( $state, $rvalue, $match ) ;
  return $rc if( $gRC_SUCCESS != $rc ) ;

  # check for ACCUM error
  my $isError =
    ( $match->{IS_ACCUM} && !scalar( @{$rule->{BEGIN_MATCH}} ) ) ;
  if( $isError ) {
    # if we had a PRE match to match on first, we're ok
    $isError = !scalar( @{$rule->{PRE_MATCH}} ) ;
  } #if
  if( $isError ) {
    $state->{ERROR} = "ACCUM not valid for first instance of match " .
      "'$lvalue' for rule '$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if

  # add to both arrays
  push( @{$rule->{MATCHES}}, $match ) ;
  push( @{$rule->{BEGIN_MATCH}}, $match ) ;
  return $gRC_SUCCESS ;
} #scriptDecodeBegin 

sub scriptDecodeOptionalMatch {
  my( $lvalue, $rvalue, $state, $isAccum ) = @_ ;

  # simply add the rvalue
  my $rule = $state->{RULE} ;
  my $match = {
    ORIG_VALUE => $rvalue,
    REGEX_OPTIONS => $state->{REGEX_OPTIONS},
    VALUE => $rvalue,
    RUNTIME_INSERT => [],
    RUNTIME_EXTRACT => [],
    IS_PRE => 0,
    IS_BEGIN => 0,
    IS_END => 0,
    IS_ACCUM => 0,
    IS_CODE => 0,
    MATCH_TIMEOUT => 0,
    CACHEMATCH => undef,
    COMPILED_SUB => undef,
  } ;

  # add *only* to the optional match array
  push( @{$rule->{OPTIONAL_MATCH}}, $match ) ;
  return $gRC_SUCCESS ;
} #scriptDecodeOptionalMatch 

sub scriptDecodeEnd {
  my( $lvalue, $rvalue, $state, $isAccum, $isCode ) = @_ ;

  # simply add the rvalue
  my $rule = $state->{RULE} ;
  my $match = {
    ORIG_VALUE => $rvalue,
    REGEX_OPTIONS => $state->{REGEX_OPTIONS},
    VALUE => $rvalue,
    RUNTIME_INSERT => [],
    RUNTIME_EXTRACT => [],
    IS_PRE => 0,
    IS_BEGIN => 0,
    IS_END => 1,
    IS_ACCUM => length( $isAccum ),
    IS_CODE => length( $isCode ),
    MATCH_TIMEOUT => $state->{MATCH_TIMEOUT},
    CACHEMATCH => undef,
    COMPILED_SUB => undef,
  } ;
  scriptResetStateMatchNextLine( $state ) ;
  my $rc = scriptCreateCompiledMatch( $state, $rvalue, $match ) ;
  return $rc if( $gRC_SUCCESS != $rc ) ;

  # add to both arrays
  push( @{$rule->{MATCHES}}, $match ) ;
  push( @{$rule->{END_MATCH}}, $match ) ;
  return $gRC_SUCCESS ;
} #scriptDecodeEnd 

sub scriptDecodeRuleTimeout {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # user can say "default"
  if( $rvalue =~ m/^DEFAULT$/i ) {
    $rvalue = $gRuleTimeoutDefault ;
  } #if

  # verify rvalue (must be numeric)
  my $rule = $state->{RULE} ;
  my $ok = ( $rvalue =~ m/^[0-9]+$/ ) ;
  if( !$ok ) {
    $state->{ERROR} = "RULE timeout must be all-numeric for " .
      "rule '$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if
  $rule->{RULE_TIMEOUT} = $rvalue ;
  return $gRC_SUCCESS ;
} #scriptDecodeRuleTimeout

sub scriptDecodeMatchTimeout {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # user can say "default"
  if( $rvalue =~ m/^DEFAULT$/i ) {
    $rvalue = $gMatchTimeoutDefault ;
  } #if

  # verify rvalue (must be numeric)
  my $rule = $state->{RULE} ;
  my $ok = ( $rvalue =~ m/^[0-9]+$/ ) ;
  if( !$ok ) {
    $state->{ERROR} = "MATCH timeout must be all-numeric for " .
      "rule '$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if
  $state->{MATCH_TIMEOUT} = $rvalue ;
  return $gRC_SUCCESS ;
} #scriptDecodeMatchTimeout 

sub scriptDecodeMatchNextLine {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # we either turn the state on or off; it always gets
  # turned off after decoding a match anyway
  if( $rvalue ) {
    $state->{MATCH_NEXT_LINE} = 1 ;
    $state->{MATCH_TIMEOUT} = 1 ;
  } else {
    $state->{MATCH_NEXT_LINE} = 0 ;
    $state->{MATCH_TIMEOUT} = 0 ;
  } #if
  return $gRC_SUCCESS ;
} #scriptDecodeMatchNextLine 

sub scriptDecodeVar {
  my( $lvalue, $rvalue, $state ) = @_ ;

  # deref the var data
  my $rule = $state->{RULE} ;
  my $varHash = $rule->{VARS} ;

  # check for dupes
  my $fullName = uc( $lvalue ) ;
  if( exists( $varHash->{$fullName} ) ) {
    $state->{ERROR} = "Variable '$lvalue' already exists for rule " .
      "'$rule->{NAME}'" ;
    return $gRC_SCRIPT ;
  } #if

  # save the action
  my $varEntry = {
    NAME => $lvalue,
    VALUE => $rvalue,
    PAREN => 0,
    IS_ARRAY => 0,
    IS_RUNTIME => 0,
  } ;
  $varHash->{$fullName} = $varEntry ;

  # special logic--if this is a RTVAR, then we insert it into the
  # RTVARS list
  if( $rvalue =~ m/\<RTVAR\>/i ) {
    $varHash = $rule->{RTVARS} ;
    $varEntry->{IS_RUNTIME} = 1 ;
    $varHash->{$fullName} = $varEntry ;
  } #if

  return $gRC_SUCCESS ;
} #scriptDecodeVar 

sub scriptDecodeLine {
  my( $line, $state ) = @_ ;

  # first, the line *must* be in the format X=Y
  my $goodFormat = ( $line =~ m/^\s*([A-Za-z0-9_\.]+)\s*=\s*(.*)/ ) ;
  my( $lvalue, $rvalue ) = ( $1, $2 ) ;
  $lvalue =~ s/^\s*(.*?)\s*$/$1/ ;
  $rvalue =~ s/^\s*(.*?)\s*$/$1/ ;
  $goodFormat = length( $lvalue ) if( $goodFormat ) ;
  #$goodFormat = length( $rvalue ) if( $goodFormat ) ;
  if( !$goodFormat ) {
    $state->{ERROR} = "Line must be in format <name>=<value>" ;
    return $gRC_SCRIPT ;
  } #if

  # handle REGEX_OPTIONS if specified
  if( $lvalue =~ m/^REGEX_OPTIONS$/i ) {
    $state->{REGEX_OPTIONS} = $rvalue ;
    return $gRC_SUCCESS ;
  } #if

  # handle INCLUDE files separately
  if( $lvalue =~ m/^INCLUDE$/i ) {
    my $fname = uc( ABR::path_getFile( $rvalue ) ) ;
    $fname = $rvalue if( !length( $fname ) ) ;
    if( exists( $gScripts{$fname} ) ) {
      # don't print the warning
      #print "W: Ignoring second INCLUDE of '$rvalue'\n" ;
      return $gRC_SUCCESS ;
    } #if

    # can we open?
    if( !open( F_INCLUDE_FILE, $rvalue ) ) {
      $state->{ERROR} = "Error opening INCLUDE file '$rvalue': $!" ;
      return $gRC_SCRIPT ;
    } #if
    close( F_INCLUDE_FILE ) ;

    # we make an entry
    my $script = {
      NAME => $rvalue,
      RULES => undef,
    } ;
    push( @gScripts, $script ) ;
    $gScripts{$fname} = $script ;

    # and attempt to load
    my $rc = scriptLoad( $script ) ;
    if( $gRC_SUCCESS != $rc ) {
      $state->{ERROR} = "Error in INCLUDE file" ;
      return $rc ;
    } #if
  } #if

  # if we're in a MACRO, then we have special logic to
  # create a rule from the single line entry
  if( $state->{IN_DEFINE_MACRO} ) {
    return scriptDecodeMacro( $lvalue, $rvalue, $state ) ;
  } #if

  # if we're in a shared code section, simply add it to the
  # array of entries
  if( $state->{IN_SHARED_CODE} ) {
    my $codeEntry = {
      NAME => $lvalue,
      VALUE => $rvalue,
    } ;
    push( @gSharedCode, $codeEntry ) ;
    return $gRC_SUCCESS ;
  } #if

  # if we're in a termination code section, simply add it to the
  # array of entries
  if( $state->{IN_TERMINATION_CODE} ) {
    my $codeEntry = {
      NAME => $lvalue,
      VALUE => $rvalue,
    } ;
    push( @gTerminationCode, $codeEntry ) ;
    return $gRC_SUCCESS ;
  } #if

  # now, we decode the line and update our rules object
  if( $lvalue =~ m/^ACTION/i ) {
    # handle an ACTION item
    return scriptDecodeAction( $lvalue, $rvalue, $state ) ;
  } elsif( $lvalue =~ m/^ENABLED$/i ) {
    # initial state of the rule (ENABLED or DISABLED)
    return scriptDecodeEnabled( $lvalue, $rvalue, $state ) ;
  } elsif( $lvalue =~ m/^PRE(_MATCH)?((_ACCUM)|(_CODE))?$/i ) {
    # handle a beginning match item
    return scriptDecodePre( $lvalue, $rvalue, $state, $3, $4 ) ;
  } elsif( $lvalue =~ m/^BEGIN(_MATCH)?((_ACCUM)|(_CODE))?$/i ) {
    # handle a beginning match item
    return scriptDecodeBegin( $lvalue, $rvalue, $state, $3, $4 ) ;
  } elsif( $lvalue =~ m/^OPTIONAL(_MATCH)?(_CODE)?$/i ) {
    # if user specified "CODE" here, that's an error. optional
    # matches must be a regex.
    if( length( $2 ) ) {
      $state->{ERROR} = "Optional match '$lvalue=$rvalue' " .
        "can't be a CODE reference" ;
      return $gRC_SCRIPT ;
    } #if

    # handle an optional match item that occurs *anytime* between
    # BEGIN and END
    return scriptDecodeOptionalMatch( $lvalue, $rvalue, $state, $2 ) ;
  } elsif( $lvalue =~ m/^END(_MATCH)?((_ACCUM)|(_CODE))?$/i ) {
    # handle an ending match item
    return scriptDecodeEnd( $lvalue, $rvalue, $state, $3, $4 ) ;
  } elsif( $lvalue =~ m/^(RULE(_)?)?TIMEOUT$/i ) {
    return scriptDecodeRuleTimeout( $lvalue, $rvalue, $state ) ;
  } elsif( $lvalue =~ m/^MATCH_TIMEOUT$/i ) {
    return scriptDecodeMatchTimeout( $lvalue, $rvalue, $state ) ;
  } elsif( $lvalue =~ m/^MATCH_NEXT_LINE$/i ) {
    return scriptDecodeMatchNextLine( $lvalue, $rvalue, $state ) ;
  } else {
    # everything else is a variable
    return scriptDecodeVar( $lvalue, $rvalue, $state ) ;
  } #if

  return $gRC_SUCCESS ;
} #scriptDecodeLine 

sub scriptParseLine {
  my( $line, $state ) = @_ ;

  # if we have a rule entry, we *always* update the end line
  my $rule = $state->{RULE} ;
  if( defined( $rule ) ) {
    $rule->{STOPLINE} = $state->{LINENO} ;
  } #if

  # ignore comments
  $line =~ s/^\s*(.*?)\s*$/$1/ ;
  return $gRC_SUCCESS if( !length( $line ) ) ;
  return $gRC_SUCCESS if( $line =~ m/^[#;]/ ) ;

  # do we have a new section?
  my $newSection = ( $line =~ m/^\[([^\]]*)\]/ ) ;
  if( $newSection ) {
    return scriptNewRule( $1, $state ) ;
  } else {
    return scriptDecodeLine( $line, $state ) ;
  } #if

  return $gRC_SUCCESS ;
} #scriptParseLine 

sub scriptLoad {
  my( $script ) = @_ ;

  # script already processed?
  return $gRC_SUCCESS if( $script->{PROCESSED} ) ;
  $script->{PROCESSED} = 1 ;

  # open the file
  my $fname = $script->{NAME} ;
  my $FILE = *STDIN ;
  my $stdin = ( $fname =~ m/^STDIN$/ ) ;
  if( !$stdin ) {
    $FILE = fileOpen( $fname, $gFILE_OPENMODE_SIMPLE ) ;
    if( !defined( $FILE ) ) {
      return _errorHelp( $gRC_ERROR,
        "Unable to open rules script '$fname': $!" ) ;
    } #if
  } #if

  # read it
  my( $line, $lineNo, $hasError ) ;
  my $state = {
    SCRIPT => $script,      # script object
    FNAME => $fname,        # file name
    ERROR => "",            # error message
    RULE => undef,          # pointer to rule object
    REGEX_OPTIONS => "",    # last read regex options
    IN_DEFINE_MACRO => 0,   # are we in a DEFINE_MACRO section?
    IN_SHARED_CODE => 0,    # code shared among the rules
    LINE_NO => 0,           # line number we're on
    MATCH_TIMEOUT => 0,     # lines for match to timeout
    MATCH_NEXT_LINE => 0,   # should two matches be together?
  } ;
  while( chomp( $line = <$FILE> ) ) {
    ++$lineNo ;
    $state->{LINE_NO} = $lineNo ;

    # trim
    $line =~ s/[\n\r]+$// ;

    # special logic for multiple lines
    my $numLines = 0 ;
    while( $line =~ /\\$/ ) {
      # replace continuation char and trim
      $line =~ s/\\$// ;
      $line =~ s/^\s*(.*?)\s*$/$1/ ;
      my $tempLine ;
      chomp( $tempLine = <$FILE> ) ;
      $tempLine =~ s/[\n\r]+$// ;
      if( defined( $tempLine ) ) {
        ++$numLines ;
        $tempLine =~ s/^\s*(.*?)\s*$/$1/ ;
        
        # comment lines never terminate a sequence
        my $appendContinue = 0 ;
        if( $tempLine =~ m/^\#/ ) {
          $appendContinue = ( $tempLine =~ /\\$/ ) ;
          $tempLine = "" ;
        } #if

        # append the Perl code
        $line .= $tempLine ;
        $line =~ s/^\s*(.*?)\s*$/$1/ ;

        # continue if necessary. note that we embed
        # a CR if we are continuing a line.
        $line .= "\n\\" if( $appendContinue ) ;
      } #if
    } #while

    # now process the line
    my $lineError = ( $gRC_SUCCESS != scriptParseLine( $line, $state ) ) ;
    if( $lineError ) {
      $hasError = 1 ;
      ABR::verboseprint( "\t$line\n" ) ;
      print( "E: $fname:$lineNo: $state->{ERROR}\n" ) ;
    } #if

    # add to the line counter
    $lineNo += $numLines ;
  } #while

  # done with the file
  if( !$stdin ) {
    close( $FILE ) ;
  } #if

  return $hasError? $gRC_SCRIPT: $gRC_SUCCESS ;
} #scriptLoad

############################################################
# dump any type of data
sub dumpPrint {
  my $tabs = shift() ;
  my $notabprint = shift() ;
  if( !$notabprint ) {
    my $i ;
    for( $i = 0 ; $i < $tabs ; $i++ ) {
      print "  " ;
    } #for
  } #if
  print @_ ;
} #dumpPrint 

sub dumpData {
  my( $data, $tabs, $notabprint, $complexOnly ) = @_ ;

  # sanity
  return if( !defined( $data ) ) ;

  # decode data item
  my $type = ref( $data ) ;
  if( $type eq "REF" ) {
    dumpPrint( $tabs, $notabprint, "REF: '$data'", "\n" ) ;
    dumpData( $$data, $tabs + 1 ) ;
  } elsif( ( $type eq "SCALAR" ) || ( $type eq "" ) ) {
    dumpPrint( $tabs, $notabprint, "'$data'", "\n" )
      if( !$complexOnly ) ;
  } elsif( $type eq "ARRAY" ) {
    dumpPrint( $tabs, $notabprint, "'$data'", "\n" ) ;
    my $i ;
    for( $i = 0 ; $i < scalar( @{$data} ) ; $i++ ) {
      dumpData( @{$data}[$i], $tabs + 1 ) ;
    } #for
  } elsif( $type eq "HASH" ) {
    my $hasName = exists( ${$data}{NAME} ) ;
    if( $hasName ) {
      dumpPrint( $tabs, $notabprint,
        "***HASH named '${$data}{NAME}'\n" ) ;
    } #if
    my $key ;
    foreach $key (sort( keys( %{$data} ) )) {
      next if( $hasName && ( $key eq "NAME" ) ) ;
      my $value = ${$data}{$key} ;
      dumpPrint( $tabs, $notabprint, "Key '$key'; Value '$value'\n" ) ;
      $notabprint = 0 ;
      dumpData( ${$data}{$key}, $tabs + 1, 0, 1 ) ;
    } #foreach
  } else {
    dumpPrint( $tabs, $notabprint, "Unsupported dump type: '$type'\n" ) ;
  } #if
} #dumpData 

############################################################
# determine rules we need to process
sub updateMatchFromExpandedItem {
  my ( $match, $newMatch, $varHash, $result ) = @_ ;

  # take any embedded RT extraction data and turn them
  # into variables in this match
  my $rtAr = $match->{RUNTIME_EXTRACT} ;
  my $rtNewAr = $newMatch->{RUNTIME_EXTRACT} ;
  my $rtextract ;
  foreach $rtextract (@{$rtNewAr}) {
    # deref vars
    my $varname = $rtextract->{VARNAME} ;
    my $match_idx = $rtextract->{MATCH_IDX} ;
    my $is_array = $rtextract->{IS_ARRAY} ;

    # we can't be here if the variable name is already used
    # in the owning rule.

    # update the match idx based on the current match
    $rtextract->{MATCH_IDX} += $result->{OPEN_PARENS} ;

    # add this rt-extraction to the current match
    push( @{$match->{RUNTIME_EXTRACT}}, $rtextract ) ;
  } #foreach

  # do the same for runtime insertion items
  my $rtAr = $match->{RUNTIME_INSERT} ;
  my $rtNewAr = $newMatch->{RUNTIME_INSERT} ;
  my $rtinsert ;
  foreach $rtinsert (@{$rtNewAr}) {
    # deref vars
    my $varname = $rtinsert->{VARNAME} ;
    my $char_pos = $rtinsert->{CHAR_POS} ;
    my $length = $rtinsert->{LENGTH} ;

    # update the char_pos
    $rtinsert->{CHAR_POS} += $result->{IDX} ;

    # add to our array
    push( @{$rtAr}, $rtinsert ) ;
  } #foreach

  return $gRC_SUCCESS ;
} #updateMatchFromExpandedItem 

sub resolveExpandMacroOrVar {
  my( $ownerRule, $match, $macro, $result ) = @_ ;

  # correct the macro name for lookups
  my $fullName = uc( $macro ) ;

  # circular reference check
  my $hash = $result->{RESOLVED_ITEMS} ;
  if( exists( ${$hash}{$fullName} ) ) {
    $result->{ERROR} = "Circular ref detected for '$macro'" ;
    return $gRC_SCRIPT ;
  } #if

  # create a new result based on the input one
  my $newResult = {
    EXPANDED => "",
    ERROR => "",
    RESOLVED_ITEMS => {},
    OPEN_PARENS => 0,
    RUNTIME => 0,
    IDX => 0,
  } ;
  my $key ;
  foreach $key (sort( keys( %{$result->{RESOLVED_ITEMS}} ) )) {
    ${$newResult->{RESOLVED_ITEMS}}{$key} = 1 ;
  } #foreach

  my $rc = $gRC_SUCCESS ;

  # first check to see if this "macro" references a var
  # in the owning rule.
  my $varHash = $ownerRule->{VARS} ;
  if( exists( ${$varHash}{$fullName} ) ) {
    # add to the list of our checked items (yes, before we
    # expand it)
    ${$newResult->{RESOLVED_ITEMS}}{$fullName} = 1 ;

    # it does exist. this could be either a compile-time
    # or a run-time variable. compile-time variables
    # have a value associated with them (like a macro).
    # thus, compile-time vars can be expanded now.
    # run-time vars do not have a value. thus, we
    # must determine what should be replaced and its
    # exact position.
    my $var = ${$varHash}{$fullName} ;
    my $isMacro = defined( $var->{VALUE} ) ;
    $isMacro = !$var->{IS_RUNTIME} if( $isMacro ) ;
    if( $isMacro ) {
      # expand the value. to do this, we create a
      # dummy MATCH item.
      my $newMatch = {
        ORIG_VALUE => $var->{VALUE},
        REGEX_OPTIONS => "",
        VALUE => $var->{VALUE},
        RUNTIME_INSERT => [],
        RUNTIME_EXTRACT => [],
      } ;
      $rc = resolveExpandItem(
        $ownerRule, 'VAR', 0, $newMatch, $newResult ) ;

      # extract any useful bits from the expanded item
      $rc = updateMatchFromExpandedItem(
        $match, $newMatch, $varHash, $result )
        if( $gRC_SUCCESS == $rc ) ;

      # update the output
      $result->{EXPANDED} = $newResult->{EXPANDED} ;
      $result->{OPEN_PARENS} += $newResult->{OPEN_PARENS} ;

      # return the result
      return $rc ;
    } else {
      # this is a run-time variable. the caller handles it.
      $result->{EXPANDED} = $fullName ;
      $result->{RUNTIME} = 1 ;
      return $gRC_SUCCESS ;
    } #if
  } #if

  # now check to see if the rule exists
  if( !exists( ${$gRules->{HASH}}{$fullName} ) ) {
    $result->{ERROR} = "Macro '$macro' is undefined" ;
    return $gRC_SCRIPT ;
  } #if

  # the rule must have a single BEGIN in it
  my $pseudoRule = ${$gRules->{HASH}}{$fullName} ;
  my $arBeginMatch = $pseudoRule->{BEGIN_MATCH} ;
  if( scalar( @{$arBeginMatch} ) != 1 ) {
    $result->{ERROR} = "Macro '$macro' must have exactly one BEGIN entry" ;
    return $gRC_SCRIPT ;
  } #if

  # add to the list of our checked items (yes, before we
  # expand it)
  ${$newResult->{RESOLVED_ITEMS}}{$fullName} = 1 ;

  # now we can resolve this item
  my $newMatch = ${$arBeginMatch}[0] ;
  my $rc = resolveExpandItem(
    $ownerRule, 'BEGIN_MATCH', 0, $newMatch, $newResult ) ;

  # extract any useful bits from the expanded item
  $rc = updateMatchFromExpandedItem(
    $match, $newMatch, $varHash, $result )
    if( $gRC_SUCCESS == $rc ) ;

  # update the output
  $result->{EXPANDED} = $newResult->{EXPANDED} ;
  $result->{OPEN_PARENS} += $newResult->{OPEN_PARENS} ;
  $result->{ERROR} = $newResult->{ERROR} ;

  return $rc ;
} #resolveExpandMacroOrVar

sub resolveExpandItem {
  my( $ownerRule, $id, $idx, $match, $result ) = @_ ;

  # caller can't expand a match item that is a code ref
  if( $match->{IS_CODE} ) {
    $result->{ERROR} = "can't expand a Code Reference" ;
    return $gRC_SCRIPT ;
  } #if

  # we simply expand the input to output. every time we
  # come to an embedded macro, then we resolve it.
  my $output = "" ;
  my $i ;
  my $backslashCount = 0 ;
  my $value = $match->{ORIG_VALUE} ;
  while( $i < length( $value ) ) {
    # update the index
    $result->{IDX} = length( $output ) ;

    # check the value
    my $char = substr( $value, $i++, 1 ) ;

    # decode char
    my $isQuotedChar = ( $char ne '\\' ) ;
    $isQuotedChar = ( $backslashCount % 2 ) if( $isQuotedChar ) ;
    if( $isQuotedChar ) {
      # empty out backslashes
      $output .= "\\" while( $backslashCount-- ) ;
      $backslashCount = 0 ;

      # output (always)
      $output .= $char ;
    } elsif( ( $char eq "\$" ) || $char eq "\@" ) {
      # this is an embedded dollar/at sign. if we have an
      # odd number of backslashes, we simply output it.
      my $ignoreChar = ( 1 == ( $backslashCount % 2 ) ) ;
      $output .= "\\" while( $backslashCount-- ) ;
      $backslashCount = 0 ;
      if( $ignoreChar ) {
        $output .= $char ;
      } else {
        # save the match character
        my $matchChar = $char ;

        # get the number of dollar/at signs. yes, we want to
        # point $i back one position so that we're pointing at
        # the dollar/at sign we're just on.
        my $matchCount = 0 ;
        --$i ;
        while( ( $char eq $matchChar ) && ( $i < length( $value ) ) ) {
          ++$matchCount ;
          ++$i ;
          $char = substr( $value, $i, 1 )
            if( $i < length( $value ) ) ;
        } #while

        # $i is now pointing one past the last dollar/at sign

        # first error condition: more than two dollars/ats
        if( $matchCount > 2 ) {
          $result->{ERROR} = "Embedded macros must be " .
            "identified with one or two $matchChar signs" ;
          return $gRC_SCRIPT ;
        } #if

        # there must be data after the current position iif
        # we have two dollar/at signs
        if( ( $matchCount == 2 ) && ( $i >= length( $value ) ) ) {
          $result->{ERROR} = "$matchChar signs must have a " .
            "macro name after them" ;
          return $gRC_SCRIPT ;
        } #if

        # a single dollar sign at the end if a regex value
        my $dollarAtEnd = ( ( $matchChar eq "\$" ) &&
          ( $matchCount == 1 ) && ( $i >= length( $value ) ) ) ;
        if( $dollarAtEnd ) {
          $output .= "\$" ;
        } else {
          # we have what *should* be a variable name. if the next
          # character is a "{" then we assume the variable is wrapped
          # within another "}". 
          $char = substr( $value, $i, 1 ) ;
          my $hasBraces = ( $char eq "{" ) ;
          ++$i if( $hasBraces ) ;
          my $keepgoing = 1 ;
          my $varName = "" ;
          while( $keepgoing ) {
            # this is such a hack, but I'm really tired now
            if( $i >= length( $value ) ) {
              if( $hasBraces ) {
                # user doesn't have a closing brace
                $result->{ERROR} =
                  "Macro missing closing brace" ;
                return $gRC_SCRIPT ;
              } #if

              # everything is a-ok
              last ;
            } #if

            # check for closing brace
            $char = substr( $value, $i++, 1 ) ;
            if( $char eq "}" ) {
              if( $hasBraces ) {
                # we're done
                last ;
              } #if
            } #if

            # check for anything else other than alphameric
            if( !( $char =~ m/[A-Za-z0-9_]/ ) ) {
              # if user bracketed the variable name, then
              # we have a problem here.
              if( $hasBraces ) {
                $result->{ERROR} =
                  "Macro contains invalid characters" ;
                return $gRC_SCRIPT ;
              } #if

              # we have some other character; end of
              # string. we decrement since we're
              # pointing one *past* the character that
              # terminates the variable name. we want
              # to point to the terminating character
              # itself.
              --$i ;
              last ;
            } else {
              # an actual variable name character
              $varName .= $char ;
            } #if
          } #while


          # if we have two dollar/at signs, then this is a
          # VARIABLE. variables must be related to a
          # parenthetical group.
          if( $matchCount == 2 ) {
            # first test: must have data after the var name
            if( $i >= length( $value ) ) {
              $result->{ERROR} =
                "Variable '$varName' is at end" ;
              return $gRC_SCRIPT ;
            } #if

            # second test: must have a paren immediately
            # available.
            $char = substr( $value, $i, 1 ) ;
            if( $char ne "(" ) {
              $result->{ERROR} =
                "Variable '$varName' must be followed by paren" ;
              return $gRC_SCRIPT ;
            } #if

            # next, we verify that this is the only variable
            # of this name in the OWNING rule.
            my $varHash = $ownerRule->{VARS} ;
            my $fullName = uc( $varName ) ;
            if( exists( ${$varHash}{$fullName} ) ) {
              $result->{ERROR} =
                "Variable '$varName' already defined in rule" ;
              return $gRC_SCRIPT ;
            } #if

            # now, we save the entry, along with its paren
            # index.
            my $varEntry = {
              NAME => $varName,
              VALUE => undef,
              PAREN => $result->{OPEN_PARENS} + 1,
              IS_ARRAY => ( $matchChar eq "\@" ),
              IS_RUNTIME => 1,
            } ;
            $varHash->{$fullName} = $varEntry ;

            # finally, we have to bind the entry to the match
            # so that we can extract the data at run-time
            my $ar = $match->{RUNTIME_EXTRACT} ;
            my $runtimeObj = {
              VARNAME => $fullName,
              MATCH_IDX => $varEntry->{PAREN},
              IS_ARRAY => $varEntry->{IS_ARRAY},
            } ;
            push( @{$ar}, $runtimeObj ) ;

            ABR::verboseprint( "Added '$varName' to rule\n" ) ;
          } else {
            # now we get the expanded string from the macro
            $result->{RUNTIME} = 0 ;
            my $rc = resolveExpandMacroOrVar(
              $ownerRule, $match, $varName, $result ) ;
            return $rc if( $rc != $gRC_SUCCESS ) ;

            # and we insert the expanded text into the output
            # unless this is a run-time var. if a run-time var,
            # then we store the information with the match.
            if( $result->{RUNTIME} ) {
              my $insertionName = 
                "<<RT INSERTION: $result->{EXPANDED}>>" ;
              my $ar = $match->{RUNTIME_INSERT} ;
              my $runtimeObj = {
                VARNAME => $result->{EXPANDED},
                CHAR_POS => length( $output ),
                LENGTH => length( $insertionName ),
              } ;
              push( @{$ar}, $runtimeObj ) ;

              $result->{EXPANDED} = $insertionName ;
            } #if
              
            $output .= $result->{EXPANDED} ;
          } #if
        } #if
      } #if
    } elsif( $char eq "\\" ) {
      # one more backslash
      ++$backslashCount ;

      # if we have two backslashes, output them now
      if( 0 == ( $backslashCount % 2 ) ) {
        $output .= "\\" while( $backslashCount-- ) ;
        $backslashCount = 0 ;
      } #if
    } elsif( $char eq "(" ) {
      # we keep track of the open parens
      my $ignoreOpenParen = ( 1 == ( $backslashCount % 2 ) ) ;
      $output .= "\\" while( $backslashCount-- ) ;
      $backslashCount = 0 ;
      ++$result->{OPEN_PARENS} if( !$ignoreOpenParen ) ;
      $output .= $char ;
    } else {
      # a normal character. if we have a backslash, then
      # output them and reset.
      $output .= "\\" while( $backslashCount-- ) ;
      $backslashCount = 0 ;
      $output .= $char ;
    } #if
  } #while

  # update state variables
  $result->{EXPANDED} = $output ;
  $result->{IDX} = length( $output ) ;

  return $gRC_SUCCESS ;
} #resolveExpandItem 

sub resolveRuleItem {
  my( $rule, $id, $idx, $match, $outputString ) = @_ ;

  # if a match is a code reference, then it needs no resolution
  if( $match->{IS_CODE} ) {
    $outputString->{EXPANDED} = "<code ref ",
      $match->{COMPILED_SUB}->{COMPILED_CODE}, ">" ;
    return $gRC_SUCCESS ;
  } #if

  # the expansion result structure
  my $result = {
    EXPANDED => "",
    ERROR => "",
    RESOLVED_ITEMS => {},
    OPEN_PARENS => 0,
    RUNTIME => 0,
    IDX => 0,
  } ;

  # the first call to expand the item
  my $rc = resolveExpandItem(
    $rule, $id, $idx, $match, $result ) ;
  if( $gRC_SUCCESS != $rc ) {
    my $script = $rule->{SCRIPT} ;
    my $fname = $script->{NAME} ;
    my $lineNo = $rule->{STARTLINE} ;
    printf( "E: $fname:$lineNo: '%s': %s\[%d\] ('%s'): %s\n",
      $rule->{FULLNAME}, $id, $idx,
      $match->{ORIG_VALUE}, $result->{ERROR} ) ;
    return $rc ;
  } else {
    ABR::verboseprint( "Expanded string '$result->{EXPANDED}'\n" ) ;
  } #if

  # return the expanded result to the caller
  $outputString->{EXPANDED} = $result->{EXPANDED} ;

  return $rc ;
} #resolveRuleItem 

sub resolveRuleArray {
  my( $rule, $key ) = @_ ;

  my $rc = $gRC_SUCCESS ;
  my( $ar, $match, $i ) ;
  $ar = $rule->{$key} ;
  my $outputString = {
    EXPANDED => "",
  } ;
  for( $i = 0 ; $i < scalar( @{$ar} ) ; $i++ ) {
    my $match = ${$ar}[$i] ;
    my $rcTemp = resolveRuleItem(
      $rule, $key, $i, $match, $outputString ) ;
    ABR::debugprint(
      "expanded='$outputString->{EXPANDED}'\n" ) ;
    $match->{VALUE} = $outputString->{EXPANDED} ;
    $rc = $rcTemp if( $rc == $gRC_SUCCESS ) ;
  } #for
  return $rc ;
} #resolveRuleArray 

sub resolveRule {
  my( $rule ) = @_ ;
  
  # simply resolve the arrays
  my $rc0 = resolveRuleArray( $rule, 'PRE_MATCH' ) ;
  my $rc1 = resolveRuleArray( $rule, 'BEGIN_MATCH' ) ;
  my $rc2 = resolveRuleArray( $rule, 'END_MATCH' ) ;
  my $rc3 = resolveRuleArray( $rule, 'OPTIONAL_MATCH' ) ;
  return ( $rc0 != $gRC_SUCCESS )? $rc0:
    ( $rc1 != $gRC_SUCCESS )? $rc1:
    ( $rc2 != $gRC_SUCCESS )? $rc2:
    $rc3 ;
} #resolveRule

sub buildListOfRulesToProcess {
  my $rule ;
  foreach $rule (@{$gRules->{ARRAY}}) {
    if( !$rule->{IS_MACRO} ) {
      # the rule has an action, so it's something we
      # need to process every time *iif* the rule
      # has begin/end matches defined
      my $arBegin = $rule->{BEGIN_MATCH} ;
      my $arEnd = $rule->{END_MATCH} ;
      if( !scalar( @{$arBegin} ) ) {
        my $script = $rule->{SCRIPT} ;
        my $fname = $script->{NAME} ;
        my $lineNo = $rule->{STARTLINE} ;
        print "W: $fname:$lineNo: ",
          "Rule must have BEGIN matches; ignoring\n" ;
      } else {
        ABR::verboseprint( "Adding rule '$rule->{NAME}' " .
          "to list; has ", scalar( @{$rule->{MATCHES}} ),
          " match entries\n" ) ;
        push( @gRulesToProcess, $rule ) ;
      } #if
    } #if
  } #foreach

  # check for no rules to process
  if( !scalar( @gRulesToProcess ) ) {
    print "E: No rules have any actions\n" ;
    return $gRC_SCRIPT ;
  } #if

  # now, we need to resolve the BEGIN/END matches
  my $rc = $gRC_SUCCESS ;
  foreach $rule (@gRulesToProcess) {
    if( !$rule->{IS_MACRO} ) {
      my $rcTemp = resolveRule( $rule ) ;
      $rc = $rcTemp if( $rc == $gRC_SUCCESS ) ;
    } #if
  } #foreach

  return $rc ;
} #buildListOfRulesToProcess 

############################################################
# log file validation
sub validateLogFiles {
  my( $arLogFiles ) = @_ ;

  # user must have at least one log file
  if( !scalar( @{$arLogFiles} ) ) {
    return _errorHelp( $gRC_CMD_LINE_ARGS,
      "No log file(s) specified" ) ;
  } #if

  # open the log files
  my( $i, %logfiles ) ;
  for( $i = 0 ; $i < scalar( @{$arLogFiles} ) ; $i++ ) {
    # extract name entry
    my $logfile = ${$arLogFiles}[$i] ;
    my $fname = $logfile->{NAME} ;

    # did user already specify this log file name?
    if( exists( $logfiles{$fname} ) ) {
      return _errorHelp( $gRC_CMD_LINE_ARGS,
        "Duplicate log file specified: '$fname'" ) ;
    } #if

    # try to open the log file (dies on error)
    $logfile->{HANDLE} = fileOpen( $fname, $gFileMode ) ;
    if( !defined( $logfile->{HANDLE} ) ) {
      return _errorHelp( $gRC_ERROR,
        "open file '$fname' returned '$!'" ) ;
    } #if

    $logfiles{$fname} = 1 ;
  } #for

  return $gRC_SUCCESS ;
} #validateLogFiles 

sub buildRegexCache {
  # anything to do?
  return $gRC_SUCCESS if( !scalar( @gRulesToProcess ) ) ;

  # build the list of cache items
  my $i ;
  for( $i = 0 ; $i < scalar( @gRulesToProcess ) ; $i++ ) {
    # extract the rule
    my $rule = $gRulesToProcess[$i] ;
    my $matches = $rule->{MATCHES} ;
    next if( !defined( $matches ) ) ;

    # iterate over the matches for this rule
    my $j ;
    for( $j = 0 ; $j < scalar( @{$matches} ) ; $j++ ) {
      # extract the match
      my $match = ${$matches}[$j] ;
      next if( $match->{IS_CODE} ) ;

      # if any "runtime insertion" entries for this match,
      # we skip it
      my $rt = $match->{RUNTIME_INSERT} ;
      if( defined( $rt ) ) {
        next if( scalar( @{$rt} ) ) ;
      } #if

      # check for this entry
      my $value = $match->{VALUE} ;
      my $cachematch ;
      my $k ;
      for( $k = 0 ; $k < scalar( @gCacheMatches ) ; $k++ ) {
        $cachematch = $gCacheMatches[$k] ;
        my $regex = $cachematch->{REGEX} ;
        last if( $regex eq $value ) ;
        $cachematch = undef ;
      } #for

      # create a new entry if necessary
      if( !defined( $cachematch ) ) {
        $cachematch = {
          REGEX => $value,
          NUM_REGEXES => 0,
          LAST_LINEID => 0,
          RESULTS => undef,
          NUM_MATCHES => 0,
          COMPILED_SUB => undef,
        } ;
        push( @gCacheMatches, $cachematch ) ;

        # create a pre-compiled routine for the regex
        my $src = 
          "sub {\n" .
          "  my \$line = shift ;\n" .
          "  \@gMatches = ( \$line =~ m/$value/ ) ;\n" .
          "}" ;
        my $code = eval( $src ) or die( "Can't compile '$src'" ) ;
        my $compiled_sub = {
          SRC_CODE => $src,
          COMPILED_CODE => $code,
        } ;
        $cachematch->{COMPILED_SUB} = $compiled_sub ;
      } #if

      # update the match entry
      $match->{CACHEMATCH} = $cachematch ;
      ++$cachematch->{NUM_REGEXES} ;
    } #for
  } #for

  # now, we clear out the cache items that have only a
  # single match
  for( $i = 0 ; $i < scalar( @gRulesToProcess ) ; $i++ ) {
    # extract the rule
    my $rule = $gRulesToProcess[$i] ;
    my $matches = $rule->{MATCHES} ;
    next if( !defined( $matches ) ) ;

    # check the matches
    my $j ;
    for( $j = 0 ; $j < scalar( @{$matches} ) ; $j++ ) {
      # extract the match
      my $match = ${$matches}[$j] ;
      my $cachematch = $match->{CACHEMATCH} ;
      next if( !defined( $cachematch ) ) ;
      if( $cachematch->{NUM_REGEXES} < 2 ) {
        #$match->{CACHEMATCH} = undef ;
      } #if
    } #for
  } #for

  # last, we iterate over the actual cache items
  for( $i = 0 ; $i < scalar( @gCacheMatches ) ; $i++ ) {
    my $cachematch = $gCacheMatches[$i] ;
    if( $cachematch->{NUM_REGEXES} >= 1 ) {
      ABR::verboseprint( "Cached regex '$cachematch->{REGEX}'\n",
        "\tNumber of regexes: $cachematch->{NUM_REGEXES}\n",
        "\tCompiled subroutine: " ) ;
      my $compiled_sub = $cachematch->{COMPILED_SUB} ;
      if( !defined( $compiled_sub ) ) {
        ABR::verboseprint( "<no>\n" ) ;
      } else {
        ABR::verboseprint( $compiled_sub->{COMPILED_CODE}, "\n" ) ;
      } #if
    } #if
  } #for
} #buildRegexCache

############################################################
# program initialization
sub init {
  my $rc = $gRC_SUCCESS ;

  # standard setup
  ABR::os_setup() ;

  # valid command line?
  $rc = parseCmdLine() ;
  return $rc if( $rc != $gRC_SUCCESS ) ;

  # now, we load the specified script files
  my( $script, $rcScript ) ;
  foreach $script (@gScripts) {
    $rcScript = scriptLoad( $script ) ;
    $rc = $rcScript if( $gRC_SUCCESS == $rc ) ;
  } #foreach

  # make sure we have something to do (rules with actions)
  $rc = buildListOfRulesToProcess()
    if( $gRC_SUCCESS == $rc ) ;

  # to optimize performance, we create cache items for
  # each duplicated regex
  $rc = buildRegexCache()
    if( $gRC_SUCCESS == $rc ) ;

  # now, we must validate the log file(s) to process
  $rc = validateLogFiles( \@gLogFiles )
    if( $gRC_SUCCESS == $rc ) ;

  # dump the data if necessary (even if we had errors?)
  if( $gDUMP ) {
    print "***DUMPING ALL LOADED DATA***\n" ;
    dumpData( $gRules ) ;
    print "\n" ;
    print "***DUMPING RULES TO PROCESS***\n" ;
    dumpData( \@gRulesToProcess ) ;
    print "***DUMP COMPLETE***\n" ;
    exit( $rc ) ;
  } #if

  return $rc ;
} #init

############################################################
# the actual program guts
sub getRegex {
  my( $ruleInst, $match ) = @_ ;

  # quick check
  my $result = $match->{VALUE} ;
  my $ar = $match->{RUNTIME_INSERT} ;
  return $result if( !scalar( @{$ar} ) ) ;

  # deref
  my $rule = $ruleInst->{RULE} ;
  my $rtvars = $ruleInst->{RTVARS} ;
  my $rulevars = $rule->{VARS} ;

  # work variables
  my $adjust = 0 ;

  # simply expand the regex, inserting values as needed
  my $rtinsert ;
  foreach $rtinsert (@{$ar}) {
    # deref vars from run-time insert object
    my $varname = $rtinsert->{VARNAME} ;
    my $charPos = $rtinsert->{CHAR_POS} ;
    my $length = $rtinsert->{LENGTH} ;

    # determine the rt to bind from and get value
    my $rtvar = ${$rtvars}{$varname} ;
    my $rulevar = $rtvar->{RULEVAR} ;
    my $replace = "" ;
    if( !defined( $rtvar ) ) {
      # this is an error! what should we do??
      print "error detected\n" ;
    } else {
      # the variable is either a SCALAR or an ARRAY.
      # for an array, we get the last value. for a
      # scalar, we get the value itself
      if( $rulevar->{IS_ARRAY} ) {
        # it's an array variable
        my $ar = $rtvar->{VALUE} ;
        my $count = scalar( @{$ar} ) ;
        if( $count ) {
          $replace = ${$ar}[$count - 1] ;
        } #if
      } else {
        # just a scalar
        $replace = $rtvar->{VALUE} ;
      } #if
    } #if

    # adjust the insertion point based on replacements
    # already done
    $charPos += $adjust ;
    
    # get the difference between the data in the string
    # and the replacement data
    my $diff = length( $replace ) - $length ;
    $adjust += $diff ;

    # do the replacement
    substr( $result, $charPos, $length, $replace ) ;
  } #foreach

  return $result ;
} #getRegex

sub doRegexMatch {
  my( $match, $regex, $line ) = @_ ;

  # if we have regex options, we do an eval here. this is *very*
  # slow and we hope that developers avoid this condition.
  if( length( $match->{REGEX_OPTIONS} ) ) {
    my $options = $match->{REGEX_OPTIONS} ;
    $line =~ s/(\\|\~|\@|\$|\%|\^|\*|\(|\)|\+|\"|\.|\/)/\\$1/g ;
    my $code = "\@gMatches = ( \"$line\" =~ m/$regex/$options ) ;" ;
    eval $code ;
  } else {
    # are we cached?
    my $cacheitem = $match->{CACHEMATCH} ;
    my $cached = defined( $cacheitem ) ;
    if( $cached ) {
      $cached = ( $cacheitem->{LAST_LINEID} == $LINE_ID ) ;
      if( $cached ) {
        # we saved a match
        @gMatches = @{$cacheitem->{RESULTS}} ;
        ++$cacheitem->{NUM_MATCHES} ;
      } #if
    } #if

    if( !$cached ) {
    #if( 1 ) {
      # perform the regex
      if( defined( $cacheitem ) ) {
        # use the pre-compiled regex, twice as fast
        my $compiled_sub = $cacheitem->{COMPILED_SUB} ;
        my $src_code = $compiled_sub->{SRC_CODE} ;
        my $compiled_code = $compiled_sub->{COMPILED_CODE} ;
        &$compiled_code( $line ) ;
      } else {
        # simple match for run-time insertion vars
        @gMatches = ( $line =~ m/$regex/ ) ;
      } #if

      # save cache data if necessary
      if( defined( $cacheitem ) ) {
        if( $cacheitem->{NUM_REGEXES} > 1 ) {
          $cacheitem->{LAST_LINEID} = $LINE_ID ;
          @{$cacheitem->{RESULTS}} = @gMatches ;
        } #if
      } #if
    } #if
  } #if
  return scalar( @gMatches ) ;
} #doRegexMatch

sub doRegexMatchRuleInst {
  my( $ruleInst, $match, $line ) = @_ ;

  my $found ;

  # if we're code, execute it now
  if( $match->{IS_CODE} ) {
    my $compiled_sub = $match->{COMPILED_SUB} ;
    my $compiled_code = $compiled_sub->{COMPILED_CODE} ;
    $found = execRuleInst( $ruleInst, $compiled_code, 1 ) ;
  } else {
    # get the regex for this match
    my $regex = getRegex( $ruleInst, $match ) ;

    # do the work
    $found = doRegexMatch( $match, $regex, $line ) ;
    extractRuntimeData( $ruleInst, $match ) if( $found ) ;
  } #if

  return $found ;
} #doRegexMatchRuleInst

sub ruleBeginMatch {
  my( $rule, $line, $ruleInst ) = @_ ;

  # start with the first entry in the list. the
  # first rule can have no run-time replacement
  my $idx = 0 ;
  my $count = scalar( @{$rule->{MATCHES}} ) ;
  while( $idx < $count ) {
    # do the match...
    my $match = ${$rule->{MATCHES}}[$idx] ;
    my $found = doRegexMatchRuleInst( $ruleInst, $match, $line ) ;
    return 0 if( !$found ) ;

    # code matches are different; we always step to the
    # next if this was a PRE. this is because when a PRE
    # match is also a code match, it becomes a simple
    # "precondition"; or a condition that must be true
    # before a match can be considered.
    if( $match->{IS_CODE} && $match->{IS_PRE} ) {
      ++$idx ;
      next ;
    } #if

    # ah, we have a match, it's not a PRE, and we can return
    # actual index that remaining matches should start with.
    return $idx + 1 ;
  } #while

  # should never get here
  return 0 ;
} #ruleBeginMatch 

sub extractRuntimeData {
  my( $ruleInst, $match ) = @_ ;

  # deref vars
  my $ar = $match->{RUNTIME_EXTRACT} ;
  return if( !scalar( @{$ar} ) ) ;

  # for each variable, extract it to the rule inst
  my $rtextract ;
  foreach $rtextract (@{$ar}) {
    # deref vars and get the actual run-time data
    my $varname = $rtextract->{VARNAME} ;
    my $matchIdx = $rtextract->{MATCH_IDX} - 1 ;
    my $data = $gMatches[$matchIdx] ;

    # now get the actual rule and the compile-time var
    my $rule = $ruleInst->{RULE} ;
    my $ruleVars = $rule->{VARS} ;
    my $ruleVar = ${$ruleVars}{$varname} ;

    # access/create the run-time var
    my $rtvars = $ruleInst->{RTVARS} ;
    my $rtvar = ${$rtvars}{$varname} ;
    if( !defined( $rtvar ) ) {
      # create a new one and save it
      $rtvar = {
        RULEINST => $ruleInst,
        RULEVAR => $ruleVar,
      } ;
      ${$rtvars}{$varname} = $rtvar ;
    } #if

    # now we have the run-time data, store it
    # if this is an ARRAY variable, we always push it.
    # otherwise, we replace it.
    if( $ruleVar->{IS_ARRAY} ) {
      #print "rtvar=", $rtvar, "\n" ;
      push( @{$rtvar->{VALUE}}, $data ) ;
      #print "length(ar)='", scalar( @{$rtvar->{VALUE}} ), "'\n" ;
    } else {
      $rtvar->{VALUE} = $data ;
    } #if
  } #foreach
} #extractRuntimeData 

sub execRuleInst {
  my( $ruleInst, $code, $isCompiled ) = @_ ;

  # deref vars
  my $rule = $ruleInst->{RULE} ;
  my $lineNo = $rule->{STARTLINE} ;
  my $script = $rule->{SCRIPT} ;
  my $fname = $script->{NAME} ;

  # set some variables available for the caller
  $LINENUMBER_START = $ruleInst->{STARTLINE} ;
  $LINENUMBER_STOP = $ruleInst->{STOPLINE} ;
  $LINENUMBER_RANGE = "$LINENUMBER_START,$LINENUMBER_STOP" ;

  # make sure rule-specific instance vars get set
  my $args ;
  my $rtvars = $ruleInst->{RTVARS} ;
  my $key ;
  foreach $key (keys( %{$rtvars} )) {
    # deref
    my $rtvar = ${$rtvars}{$key} ;
    my $rulevar = $rtvar->{RULEVAR} ;
    my $value = $rtvar->{VALUE} ;

    # relate to the variable name
    my $name = $rulevar->{NAME} ;

    # and make this a variable we can access
    $args .= " " if( length( $args ) ) ;
    if( $rulevar->{IS_ARRAY} ) {
      # handle array vars
      $args .= "my \@$name ;" ;
      my $arg ;
      foreach $arg (@{$value}) {
        $arg =~ s/(\\|\~|\@|\$|\%|\^|\*|\(|\)|\+|\"|\.|\/)/\\$1/g ;
        $args .= " push( \@$name, \"$arg\" ) ;" ;
      } #foreach
    } else {
      # scalar (simple) vars
      $value =~ s/(\\|\~|\@|\$|\%|\^|\*|\(|\)|\+|\"|\.|\/)/\\$1/g ;
      $args .= "my \$$name = \"$value\" ;" ;
    } #if
  } #foreach

  my $term ;
  #foreach $key (keys( %{$rtvars} )) {
    # deref
    #my $rtvar = ${$rtvars}{$key} ;
    #my $rulevar = $rtvar->{RULEVAR} ;
    #my $value = $rtvar->{VALUE} ;

    # relate to the variable name
    #my $name = $rulevar->{NAME} ;
    #if( $rulevar->{IS_ARRAY} ) {
      # handle array vars
      #$term .= "undef( \@$name ) ;" ;
    #} else {
      ## scalar (simple) vars
      #$term .= "undef( \$$name ) ;" ;
    #} #if
  #} #foreach

  # execute some code
  my $rc = 1 ;
  my $codeToEval = "$args " ;
  if( $isCompiled ) {
    $codeToEval .= '$rc = &$code() ;' ;
  } else {
    $codeToEval .= $code ;
  } #if
  $codeToEval .= " $term" ;
  ABR::verboseprint( "Executing user-defined code: '", $codeToEval, "'\n" ) ;
  no strict ;
  eval "$codeToEval" ;
  my $result = $@ ;
  use strict ;
  if( length( $result ) ) {
    print( "E: $fname:$lineNo: " .
      "Code '$codeToEval' failed: '$result'\n" ) ;
    return 0 ;
  } #if
  return $rc ;
} #execRuleInst

sub execAction {
  my( $ruleInst, $actionType ) = @_ ;

  # access the action
  my $rule = $ruleInst->{RULE} ;
  my $action = $rule->{ACTION} ;
  my $actionObj = $action->{$actionType} ;
  if( !defined( $actionObj ) ) {
    #ABR::verboseprint( "$fname:$lineNo: " .
      #"No $actionType action for '$rule->{NAME}'\n" ) ;
    return 0 ;
  } #if

  # deref the code vars
  my $actionName = $actionObj->{NAME} ;
  my $actionCode = $actionObj->{VALUE} ;
  $actionCode .= ";" if( !( $actionCode =~ /;$/ ) ) ;
  return execRuleInst( $ruleInst, $actionCode, 0 ) ;
} #execAction

sub handleCreated {
  my( $ruleInst ) = @_ ;
  my $rc = execAction( $ruleInst, 'CREATE' ) ;
  return $rc ;
} #handleCreated

sub updatePrevRuleInst {
  my( $rule, $ruleInst ) = @_ ;

  # save in our previous instance hash
  my $fullname = $rule->{FULLNAME} ;
  my $ruleInstPrev = $gRulePrevInstances{$fullname} ;
  if( defined( $ruleInstPrev ) ) {
    # i found that i must delete this ref manually
    my $key ;
    foreach $key (keys( %{$ruleInstPrev->{RTVARS}} )) {
      undef ${$ruleInstPrev->{RTVARS}}{$key} ;
    } #foreach
    #delete $ruleInstPrev->{RTVARS} ;
    #delete $gRulePrevInstances{$fullname} ;
  } #if
  $gRulePrevInstances{$fullname} = $ruleInst ;
} #updatePrevRuleInst 

sub destroyRuleInst {
  my( $ruleInst ) = @_ ;

  # work vars
  my $tmpRuleInst ;
  my $i ;

  # get indexes for update
  my $arIndex = $ruleInst->{AR_INDEX} ;
  my $hashIndex = $ruleInst->{HASH_INDEX} ;
  splice( @gRuleInstances, $arIndex, 1 ) ;

  # update the instance array indices within the hash
  my $rule = $ruleInst->{RULE} ;
  my $name = $rule->{FULLNAME} ;
  my $arRules = $gRuleInstances{$name} ;
  splice( @{$arRules}, $hashIndex, 1 ) ;
  for( $i = $hashIndex ; $i < scalar( @{$arRules} ) ; $i++ ) {
    $tmpRuleInst = ${$arRules}[$i] ;
    --$tmpRuleInst->{HASH_INDEX} ;
  } #for

  # update all other indices for other rules
  for( $i = $arIndex ; $i < scalar( @gRuleInstances ) ; $i++ ) {
    $tmpRuleInst = $gRuleInstances[$i] ;
    --$tmpRuleInst->{AR_INDEX} ;
  } #for

  # fire destructor
  execAction( $ruleInst, 'DESTROY' ) ;

  updatePrevRuleInst( $rule, $ruleInst ) ;
} #destroyRuleInst

sub handleComplete {
  my( $ruleInst ) = @_ ;

  # execute the code and destroy rule
  my $rc = execAction( $ruleInst, 'COMPLETE' ) ;
  destroyRuleInst( $ruleInst ) ;

  return $rc ;
} #handleComplete

sub handleIncomplete {
  my( $ruleInst ) = @_ ;

  return execAction( $ruleInst, 'INCOMPLETE' ) ;
} #handleIncomplete

sub handleMissing {
  my( $ruleInst ) = @_ ;

  return execAction( $ruleInst, 'MISSING' ) ;
} #handleMissing

sub ruleInstCheckComplete {
  my( $logfile, $ruleInst ) = @_ ;

  # are we done?
  my $finished = ( $ruleInst->{MATCH_IDX} >= $ruleInst->{MATCH_CNT} ) ;
  if( $finished ) {
    # we're done
    $ruleInst->{STOPLINE} = $logfile->{LINENO} ;
    handleComplete( $ruleInst ) ;
    return 1 ;
  } #if
  return 0 ;
} #ruleInstCheckComplete

sub checkInstances {
  my( $line, $logfile ) = @_ ;

  # verify we have anything to do
  if( $gNumInstances != scalar( @gRuleInstances ) ) {
    $gNumInstances = scalar( @gRuleInstances ) ;
  } #if

  # iterate over all created instances, seeing if a rule has
  # completed.
  my $ruleInst ;
  my $ruleInstIdx ;
  for( $ruleInstIdx = 0 ; $ruleInstIdx < scalar( @gRuleInstances ) ; $ruleInstIdx++ ) {
    $ruleInst = $gRuleInstances[$ruleInstIdx] ;
    $gRuleInstCurrent = $ruleInst ;

    if( !length( $ruleInst->{RULE}->{NAME} ) ) {
      $ruleInstIdx = $ruleInstIdx ;
    } #if

    # make sure we don't access arrays out-of-bounds.
    # first-time logic says that we'll fall thru here if
    # we match on a rule instance and there is only one
    # MATCH data to go against.
    if( ruleInstCheckComplete( $logfile, $ruleInst ) ) {
      next ;
    } #if

    # reset the first-time flag here
    $ruleInst->{FIRST_TIME} = 0 ;

    # deref everything
    my $rule = $ruleInst->{RULE} ;
    my $idx = $ruleInst->{MATCH_IDX} ;
    my $cnt = $ruleInst->{MATCH_CNT} ;

    # now we have some strangeness. while we're on an ACCUM
    # entry and we do *NOT* have a match, we keep going forward.
    # if we exhaust all our tests, we're done and we exit the loop.
    my $found = 0 ;
    while( !$found && ( $idx < $cnt ) ) {
      my $match = ${$rule->{MATCHES}}[$idx] ;
      $found = doRegexMatchRuleInst( $ruleInst, $match, $line ) ;

      # extract the run-time data if we found a match
      if( $found ) {  
        # we *did* find a match. we only bump up the index if
        # we are *not* on an ACCUM entry. remember that an
        # ACCUM entry means that we keep matching on the same
        # type of line, until any line AFTER this ACCUM entry
        # match.
        #
        # the same logic applies if this is a CODE match;
        # this means that we can match to a popped condition and
        # also check the current line.
        ++$idx if( !$match->{IS_ACCUM} || $match->{IS_CODE} ) ;
      } else {
        # we *only* continue if we didn't find a match *and*
        # the current match is an "ACCUM" entry. an ACCUM entry
        # says "match zero or more lines of this type". Therefore,
        # it's possible for the user to define multiple ACCUM lines
        # that never actually get a match.
        last if( !$match->{IS_ACCUM} ) ;

        # we are continuing, because we didn't have a match but
        # we are *on* an ACCUM entry
        ++$idx ;
      } #if
    } #while

    # if we found a match, then we update the index
    $ruleInst->{MATCH_IDX} = $idx if( $found ) ;

    # and we indicate we're done if necessary
    if( ruleInstCheckComplete( $logfile, $ruleInst ) ) {
      --$ruleInstIdx ;
      next ;
    } #if

    # update the line # if we got a match
    $ruleInst->{LAST_MATCH_LINE} = $logfile->{LINENO}
      if $found ;

    # a special case--check the current MATCH and see if it
    # "timed-out". this is different from the RULE timeout;
    # the MATCH timeout exists to allow callers to indicate that
    # one match *must* occur within a particular number of lines
    # from the previous match. if the condition isn't met, then
    # we just dump the match entry without invoking the
    # INCOMPLETE or TIMEOUT user functions.
    my $idx = $ruleInst->{MATCH_IDX} ;
    my $match = ${$rule->{MATCHES}}[$idx] ;
    my $destroyed = 0 ;
    if( $match->{MATCH_TIMEOUT} ) {
      my $elapsed = $logfile->{LINENO} -
        $ruleInst->{LAST_MATCH_LINE} ;
      if( $elapsed >= $match->{MATCH_TIMEOUT} ) {
        # execute the special MATCH_TIMEOUT handler
        execAction( $ruleInst, 'MATCH_TIMEOUT' ) ;
        
        # and destroy
        destroyRuleInst( $ruleInst ) ;

        # no more processing
        $destroyed = 1 ;
      } #if
    } #if
    if( $destroyed ) {
      --$ruleInstIdx ;
      next ;
    } #if

    # another way to match. if OPTIONAL_MATCH entries exist and
    # we didn't have a match anywhere else, then we need to
    # check the OPTIONAL_MATCH entries (all of them) against the
    # current line and do the data extraction. we *only* do this
    # if we're currently on a BEGIN match, and the next match is
    # an END match.
    my $checkOptional = !$found ;
    $checkOptional = ( $ruleInst->{MATCH_IDX} >= 1 )
      if( $checkOptional ) ;
    if( $checkOptional ) {
      $idx = $ruleInst->{MATCH_IDX} ;
      my $match = ${$rule->{MATCHES}}[$idx] ;
      $checkOptional = $match->{IS_END} ;
      if( $checkOptional ) {
        foreach $match ( @{$rule->{OPTIONAL_MATCH}} ) {
          my $found2 = doRegexMatchRuleInst(
            $ruleInst, $match, $line ) ;
          $found = 1 if( $found2 ) ;
        } #foreach
        $ruleInst->{LAST_MATCH_LINE} = $logfile->{LINENO}
          if $found ;
      } #if
    } #if
    next if( $found ) ;

    # if we don't have a match, then we see if we have hit the
    # "timeout" for this instance
    my $elapsed = ( $logfile->{LINENO} -
      $ruleInst->{LAST_MATCH_LINE} ) ;
    if( $elapsed >= $rule->{RULE_TIMEOUT} ) {
      # fire "timeout" action (always)
      execAction( $ruleInst, 'TIMEOUT' ) ;

      # we also fire the "incomplete" action
      # iif the previous item was a PRE
      my $idx = $ruleInst->{MATCH_IDX} - 1 ;
      my $match = ${$rule->{MATCHES}}[$idx] ;
      execAction( $ruleInst, 'INCOMPLETE' ) if( !$match->{IS_PRE} ) ;
      
      # and destroy
      destroyRuleInst( $ruleInst ) ;

      # update counters so that we keep going with the next rule
      --$ruleInstIdx ;
    } #if
  } #foreach

  # reset
  $gRuleInstCurrent = undef ;
} #checkInstances

sub ruleSingleMatch {
  my( $logfile, $rule, $ruleInstTemp, $startIdx ) = @_ ;

  # if user wants ctor/dtor code invoked for rules, the
  # -nofast command line switch must be used.
  return 0 if( !$gFAST ) ;

  # if this rule has only a single match, then
  # we extract data, execute code, and we're done.
  if( $startIdx >= scalar( @{$rule->{MATCHES}} ) ) {
    # indicate we executed the rule at least once
    $rule->{FOUND} = 1 ;

    # create a dummy rule instance
    my $ruleInst = {
      FIRST_TIME => 1,
      RULE => $rule,
      MATCH_IDX => 1,
      MATCH_CNT => 1,
      RTVARS => $ruleInstTemp->{RTVARS},
      STARTLINE => $logfile->{LINENO},
      STOPLINE => $logfile->{LINENO},
      LAST_MATCH_LINE => $logfile->{LINENO},
      RULES_CREATED => {},
      LOGFILE => $logfile,
    } ;
    $gRuleInstCurrent = $ruleInst ;
    my $match = ${$rule->{MATCHES}}[0] ;
    if( !$match->{IS_CODE} ) {
      # can only extract run-time data from a regex match
      extractRuntimeData( $ruleInst, $match ) ;
    } #if

    # execute the user-defined code
    execAction( $ruleInst, 'COMPLETE' ) ;

    # save the instance in the previous instance list
    updatePrevRuleInst( $rule, $ruleInst ) ;

    # reset
    $gRuleInstCurrent = undef ;

    # indicate this was a single-match rule
    return 1 ;
  } #if

  # this wasn't a single-match rule
  return 0 ;
} #ruleSingleMatch 

sub checkLineAgainstRules {
  my( $line, $logfile ) = @_ ;

  # reset our list of "winning" old instances
  @gWinningRulesForInstanceCreation = undef ;

  # check the instances first
  checkInstances( $line, $logfile ) ;

  # first, we need to see if we must create any rule
  # instances
  my $rule ;
  foreach $rule (@gRulesToProcess) {
    # is this rule currently enabled?
    next if( !$rule->{ENABLED} ) ;

    # function returns zero if no matches; or the index
    # we should start with
    my $ruleInstTemp = {
      RULE => $rule,
      RTVARS => {},
    } ;
    $gRuleInstCurrent = $ruleInstTemp ;
    my $startIdx = ruleBeginMatch( $rule, $line, $ruleInstTemp ) ;
    if( $startIdx ) {
      next if( ruleSingleMatch(
        $logfile, $rule, $ruleInstTemp, $startIdx ) ) ;

      # we have a match. however, if this is on a
      # PRE-MATCH entry, and we have another rule
      # instance already active, we replace the
      # existing rule instance. otherwise, we
      # create a new one.
      #
      # this logic is called "candidate matching." it
      # exists because in many cases a rule is a "candidate"
      # for many lines. for example, assume a rule where
      # the first match is a timestamp from a log file,
      # and the second line is some unique string. the
      # first match might match to thousands of lines in
      # the log file; while there's probably just a few of
      # the second line. the "PRE" matches exist to support
      # this type of situation, and to prevent the log
      # engine from creating thousands of false rule
      # instances.
      my $arRuleInst = $gRuleInstances{$rule->{FULLNAME}} ;
      if( !defined( $arRuleInst ) ) {
        # create the array for the instances
        my @ar ;
        $arRuleInst = \@ar ;
        $gRuleInstances{$rule->{FULLNAME}} = $arRuleInst ;
      } #if

      # locate the rule instance in the array
      my $i ;
      my $ruleInst ;
      for( $i = 0 ; $i < scalar( @{$arRuleInst} ) ; $i++ ) {
        # get the rule instance for this rule
        $ruleInst = ${$arRuleInst}[$i] ;

        # get the current match (always at least one, or the
        # rule instance doesn't exist)
        my $idx = $ruleInst->{MATCH_IDX} ;
        my $match = ${$rule->{MATCHES}}[$idx] ;

        # if this is a "pre-match" match, then we replace the
        # instance.
        last if( $match->{IS_PRE} ) ;
        if( $idx > 0 ) {
          $match = ${$rule->{MATCHES}}[$idx - 1] ;
          last if( $match->{IS_PRE} ) ;
        } #if

        # this is an actual matching rule, so we reset our flag
        $ruleInst = undef ;
      } #for

      # do we create a new instance?
      my $created = 0 ;
      my $newInst = !defined( $ruleInst ) ;
      if( $newInst ) {
        # create a new entry
        $ruleInst = {
          FIRST_TIME => 1,
          RULE => $rule,
          MATCH_IDX => $startIdx,
          MATCH_CNT => scalar( @{$rule->{MATCHES}} ),
          RTVARS => $ruleInstTemp->{RTVARS},
          STARTLINE => $logfile->{LINENO},
          STOPLINE => $logfile->{LINENO},
          LAST_MATCH_LINE => $logfile->{LINENO},
          RULES_CREATED => {},
          LOGFILE => $logfile,
        } ;
        $ruleInst->{HASH_INDEX} = scalar( @{$arRuleInst} ) ;
        push( @{$arRuleInst}, $ruleInst ) ;
        $ruleInst->{AR_INDEX} = scalar( @gRuleInstances ) ;
        push( @gRuleInstances, $ruleInst ) ;
        $created = 1 ;

        # indicate to all rules in the "winning" list that
        # a rule instance of this type is being created.
        my $oldInst ;
        foreach $oldInst (@gWinningRulesForInstanceCreation) {
          ${$oldInst->{RULES_CREATED}}{$rule->{FULLNAME}} = 1 ;
        } #foreach

        # indicate we found this rule
        $rule->{FOUND} = 1 ;
      } #if

      # now we know we have an instance created. we
      # account for resetting it if necessary.
      if( $ruleInst->{MATCH_IDX} < $ruleInst->{MATCH_CNT} ) {
        my $idx = $ruleInst->{MATCH_IDX} - 1 ;
        my $match = ${$rule->{MATCHES}}[$idx] ;
        if( $match->{IS_PRE} ) {
          # reset the instance
          $ruleInst->{MATCH_IDX} = $startIdx ;
          $ruleInst->{FIRST_TIME} = 1 ;
          $ruleInst->{STARTLINE} = $logfile->{LINENO} ;
          $ruleInst->{STOPLINE} = $logfile->{LINENO} ;
          $ruleInst->{LAST_MATCH_LINE} = $logfile->{LINENO} ;
          $ruleInst->{RTVARS} = $ruleInstTemp->{RTVARS} ;
        } #if
      } #if

      # reload the data extract data for this match. note that
      # we always extract the data from the first match.
      if( $ruleInst->{FIRST_TIME} ) {
        my $match = ${$rule->{MATCHES}}[$startIdx - 1] ;
        if( !$match->{IS_CODE} ) {
          # can only extract run-time data from a regex match
          extractRuntimeData( $ruleInst, $match ) ;
        } #if
        if( $created ) {
          handleCreated( $ruleInst ) if( $created ) ;
        } #if
      } #if

      # see if the rule is complete
      ruleInstCheckComplete( $logfile, $ruleInst ) ;
    } #if
  } #foreach
} #checkLineAgainstRules 

sub showLogStatus {
  my( $logfile, $flag ) = @_ ;

  # account for first time logic
  if( 2 == $flag ) {
    print "$logfile->{NAME}: $logfile->{LINENO}" ;
    return ;
  } #if

  # should we print?
  my $bPrint = ( 0 == ( $logfile->{LINENO} % $gSTATUS ) ) ;
  $bPrint = ( 1 == $flag ) if( !$bPrint ) ;
  return if( !$bPrint ) ;

  print "\r$logfile->{NAME}: $logfile->{LINENO}" ;

  # account for last-time logic (print a newline)
  print "\n" if( 1 == $flag ) ;
} #showLogStatus 

sub readNextLine {
  # shoot over each file, and get the next line to process
  my $result = 0 ;
  my $i ;
  for( $i = 0 ; $i < scalar( @gLogFiles ) ; $i++ ) {
    # deref
    my $logfile = $gLogFiles[$i] ;

    # anything to do?
    next if( !defined( $logfile->{HANDLE} ) ) ;

    # save in global
    $gLogFile = $logfile ;

    # get status. if the file is through, then close
    my $status = fileReady( $logfile->{HANDLE} ) ;
    if( $status > 0 ) {
      # we have data available, now we read it
      my $line = fileReadLine( $logfile->{HANDLE} ) ;
      $LINE_LASTREAD = $line ;

      # if we got an undefined string back, we're at EOF
      if( !defined( $line ) ) {
        # we're at EOF, close unless user wants to keep going
        if( !$logfile->{KEEP_OPEN} ) {
          showLogStatus( $logfile, 1 ) if( $gSTATUS ) ;
          fileClose( \$logfile->{HANDLE} ) ;
          $logfile->{HANDLE} = undef ;
        } else {
          # user does want to go forever
          $result = 1 ;
        } #if
      } else {
        # we got data and we should keep going
        ++$logfile->{LINENO} ;
        ++$LINE_ID ;
        if( $logfile->{LINENO} == 1 ) {
          if( $gSTATUS ) {
            showLogStatus( $logfile, 2 ) ;
          } #if
        } #if
        $LINENUMBER_CURRENT = $logfile->{LINENO} ;
        showLogStatus( $logfile ) if( $gSTATUS ) ;
        if( $gSTUDY > 0 ) {
          study $line if( length( $line ) >= $gSTUDY ) ;
        } #if
        checkLineAgainstRules( $line, $logfile ) ;
        $result = 1 ;

        # we only do one file at a time now...
        return $result if( !$gLogengineQuitFlag ) ;
        return 0 ;
      } #if
    } elsif( $status < 0 ) {
      # we had an error
      my $fname = $logfile->{NAME} ;
      print( "E: error checking logfile '$fname': $!\n" ) ;

      # close the file
      fileClose( \$logfile->{HANDLE} ) ;

      # don't do more I/O on this log file
      $logfile->{HANDLE} = undef ;
    } elsif( $status == 0 ) {
      # close unless user wants to stay open
      if( !$logfile->{KEEP_OPEN} ) {
        showLogStatus( $logfile, 1 ) if( $gSTATUS ) ;
        fileClose( \$logfile->{HANDLE} ) ;
        $logfile->{HANDLE} = undef ;
      } else {
        # user wants to stay open forever, so we
        # must keep going
        $result = 1 ;
      } #if
    } #if
  } #for

  return $result ;
} #readNextLine 

sub run {
  my $rc = $gRC_SUCCESS ;

  # now we step through each of the log files to process
  my $keepgoing = 1 ;
  while( $keepgoing ) {
    # if any data is left to be read, then process it
    $keepgoing = readNextLine ;
  } #while

  # now we do some cool stuff. show the incomplete and
  # unfound rules.
  my $ruleInst ;
  foreach $ruleInst (@gRuleInstances) {
    # if the rule is still on the PRE-MATCH data,
    # then it's not a candidate for INCOMPLETE
    my $rule = $ruleInst->{RULE} ;
    my $idx = $ruleInst->{MATCH_IDX} ;
    my $match = ${$rule->{MATCHES}}[$idx] ;

    # if this is a "pre-match" match, it's not a problem
    next if( $match->{IS_PRE} ) ;
    if( $idx > 0 ) {
      $match = ${$rule->{MATCHES}}[$idx - 1] ;
      next if( $match->{IS_PRE} ) ;
    } #if

    # we have a problem, incomplete match
    if( !handleIncomplete( $ruleInst ) ) {
      my $rule = $ruleInst->{RULE} ;
      my $name = $rule->{NAME} ;
      my $lineNo = $rule->{STARTLINE} ;
      my $script = $rule->{SCRIPT} ;
      my $fname = $script->{NAME} ;
      print( "W: $fname:$lineNo: Rule '$name' " .
        "($ruleInst->{LOGFILE}->{NAME}: " .
        "$ruleInst->{STARTLINE}) incomplete.\n" ) ;
    } #if
  } #foreach

  # handle "not found" rules
  my $rule ;
  foreach $rule (@gRulesToProcess) {
    if( !$rule->{FOUND} ) {
      my $ruleInst = {
        RULE => $rule,
      } ;
      if( !handleMissing( $ruleInst ) ) {
        my $name = $rule->{NAME} ;
        my $lineNo = $rule->{STARTLINE} ;
        my $script = $rule->{SCRIPT} ;
        my $fname = $script->{NAME} ;
        print( "W: $fname:$lineNo: Rule '$name' never executed.\n" ) ;
      } #if
    } #if
  } #foreach

  return $rc ;
} #run

############################################################
# clean up any resources we've used
sub done {
  my( $rcIn ) = @_ ;

  my $rc = $gRC_SUCCESS ;

  # simply execute the TERMINATION code
  if( $gRC_SUCCESS == $rcIn ) {
    my $codeEntry ;
    foreach $codeEntry (@gTerminationCode) {
      my $code = $codeEntry->{VALUE} ;
      ABR::verboseprint( "Executing termination code: '",
        $code, "'\n" ) ;
      no strict ;
      eval "$code" ;
      my $result = $@ ;
      use strict ;
      if( length( $result ) ) {
        print "Termination Code '$codeEntry->{NAME}' ",
          "failure: '$result'\n" ;
        print " Code: '$code'\n" ;
      } #if
    } #foreach
  } #if

  return $rc ;
} #done

############################################################
# handy functions for the SCRIPTS to invoke

# Extract a user option
# @param Name of the option to extract (case-sensitive)
# @return Reference to array of options, or UNDEF if no
#   options provided for the named option.
sub LOGENGINE_GET_USER_OPT {
  my( $name ) = @_ ;
  return undef if( !defined( $name ) ) ;
  my $ar = $gUserOptions{$name} ;
  return undef if( !defined( $ar ) ) ;
  $gUserOptionsUsed{$name} = 1 ;
  return $ar ;
} #LOGENGINE_GET_USER_OPT 

# Reset the match instances for a named rule.
# @param Name of the rule to reset instances on
# @return Non-zero if the reset worked
sub LOGENGINE_RESET_RULE_INSTANCES {
  my( $name ) = @_ ;

  # all rules are upper case
  $name = uc( $name ) ;

  # lookup
  my $arInstances = $gRuleInstances{$name} ;
  return 0 if( !defined( $arInstances ) ) ;

  # destroy everything
  while( scalar( @{$arInstances} ) ) {
    my $ruleInst = ${$arInstances}[0] ;
    destroyRuleInst( $ruleInst ) ;
  } #while
  return 1 ;
} #LOGENGINE_RESET_RULE_INSTANCES

# Turn an array of data into a single string.
# @param Array of data to work with
# @return Single string
sub LOGENGINE_XLAT_AR_TO_STRING {
  my( @ar ) = @_ ;
  my $entry ;
  my $result ;
  foreach $entry (@ar) {
    $result .= $entry ;
  } #foreach
  return $result ;
} #LOGENGINE_XLAT_AR_TO_STRING 

# Write a line to a buffer (for output to a file later)
# @param Buffer Identifier (a unique string per buffer)
# @param List of data to write
# @return TRUE if successful, FALSE if failure
sub LOGENGINE_WRITE_TO_BUFFER {
  # verify we have at least two parms
  my $parms = scalar( @_ ) ;
  return 0 if( $parms < 2 ) ;

  # get the buffer name
  my $buffer = shift ;

  # write data to it
  push( @{$gBuffers{$buffer}}, (@_) ) ;
  return 1 ;
} #LOGENGINE_WRITE_TO_BUFFER 

# Clear out a buffer
# @param Buffer Identifier (a unique string per buffer)
# @return TRUE if successful, FALSE if failure
sub LOGENGINE_CLEAR_BUFFER {
  my( $buffer ) = @_ ;
  return 0 if( !defined( $buffer ) ) ;
  $gBuffers{$buffer} = undef ;
  return 1 ;
} #LOGENGINE_CLEAR_BUFFER 

# Write a list of data to a list of file destinations. Usage is:<br>
#   LOGENGINE_WRITE_LIST_TO_FILES( \*FILEHANDLE, \*FILEHANDLE, ...,
#    $data, $data, ... ) ;
# @param List of file handles to write to
# @param List of data to write
# @return TRUE if the write was successful, FALSE on failure
sub LOGENGINE_WRITE_LIST_TO_FILES {
  # must have at least one file handle and one data item
  return 0 if( scalar( @_ ) < 2 ) ;

  # get the file destinations
  my @files, my @parms ;
  my $isFile = 1 ;
  while( scalar( @_ ) ) {
    my $parm = shift( @_ ) ;
    if( $isFile ) {
      # must be a GLOB ref
      my $parmType = ref( $parm ) ;
      $isFile = $parmType eq "GLOB" ;
      $isFile = ( fileno( $parm ) > 0 ) if( $isFile ) ;
      if( $isFile ) {
        push( @files, $parm ) ;
      } #if
    } #if
    push( @parms, $parm ) if( !$isFile ) ;
  } #while

  # print if we have anything
  return 0 if( !scalar( @files ) || !scalar( @parms ) ) ;
  my $file ;
  foreach $file (@files) {
    print {$file} @parms ;
  } #foreach
  return 1 ;
} #LOGENGINE_WRITE_LIST_TO_FILES 

# Write a list of data to STDOUT. Usage is:<br>
#   LOGENGINE_WRITE_LIST_TO_STDOUT( $data, $data, ... ) ;
# @param List of file handles to write to (STDOUT gets prepended)
# @param List of data to write
# @return TRUE if the write was successful, FALSE on failure
sub LOGENGINE_WRITE_LIST_TO_STDOUT {
  return LOGENGINE_WRITE_LIST_TO_FILES( \*STDOUT, (@_) ) ;
} #LOGENGINE_WRITE_LIST_TO_STDOUT 

# Write a buffer to a list of files. Usage is:<br>
#   LOGENGINE_WRITE_BUFFER_TO_FILES( $buffer, \*FILE, \*FILE, ... ) ;
# @param Buffer name to write
# @param List of file handles to write to (STDOUT gets prepended)
# @return TRUE if the write was successful, FALSE on failure
sub LOGENGINE_WRITE_BUFFER_TO_FILES {
  # must have at least two parms (buffer, filehandle)
  return 0 if( scalar( @_ ) < 2 ) ;

  # buffer must exist
  my $buffer = shift ;
  return 0 if( !exists( $gBuffers{$buffer} ) ) ;

  # and write the buffer info to the specified files
  return LOGENGINE_WRITE_LIST_TO_FILES(
    (@_), (@{$gBuffers{$buffer}}) ) ;
} #LOGENGINE_WRITE_BUFFER_TO_FILES 

# Write a buffer to a STDOUT. Usage is:<br>
#   LOGENGINE_WRITE_BUFFER_TO_STDOUT( $buffer [, \*FILE, ...] ) ;
# @param Buffer name to write
# @param List of file handles to write to (STDOUT gets prepended)
# @return TRUE if the write was successful, FALSE on failure
sub LOGENGINE_WRITE_BUFFER_TO_STDOUT {
  my $buffer = shift ;
  return 0 if( !defined( $buffer ) ) ;
  return LOGENGINE_WRITE_BUFFER_TO_FILES(
    $buffer, \*STDOUT, (@_) ) ;
} #LOGENGINE_WRITE_BUFFER_TO_STDOUT 

# Has the named rule ever matched?
# @param ruleName Rule name to check
# @return Non-zero if the rule has *ever* matched
sub LOGENGINE_HAS_RULE_EVER_MATCHED {
  my $ruleName = uc( shift ) ;

  # we simply check to see if the rule exists in our
  # "previous instances", which keeps a list of the
  # last matched instance for each rule.
  return exists( $gRulePrevInstances{$ruleName} ) ;
} #LOGENGINE_HAS_RULE_EVER_MATCHED 

# Get the raw data structure for the last completed instance of
# the specified rule
# @param ruleName Rule name to get
# @return RULEINST object (undef if error)
sub LOGENGINE_GET_LAST_RULE_INST {
  my $ruleName = uc( shift ) ;
  return $gRulePrevInstances{$ruleName} ;
} #LOGENGINE_GET_LAST_RULE_INST 

# Compare a rule to a list of rule name to see whether a match has
# occurred. Logic is:<p>
# <UL>
# <LI>We always go against the current instance.
# <LI>For each additional rule:
#   <UL>
#   <LI>Has the rule matched?
#   <LI>Is the last stopline greater than the first rule's startline?
#   <LI>If so, save the rule
#   </UL>
# </UL>
# @param <...list...> List of rules to compare against the controller
# @return The RULEINST object of the rule matching above algo;
#   undef if no match.
sub LOGENGINE_COMPARE_RULES {
  # sanity
  return undef if( !defined( $gRuleInstCurrent ) ) ;

  # function result (assume no match)
  my $result = undef ;

  # get the controlling rule and its last matched instance
  my $controllingRuleName = $gRuleInstCurrent->{RULE}->{FULLNAME} ;
  my $controllingRuleInst = $gRulePrevInstances{$controllingRuleName} ;

  # iterate over the list of rules
  my $ruleName ;
  while( $ruleName = uc( shift ) ) {
    # has this rule ever matched?
    if( exists( $gRulePrevInstances{$ruleName} ) ) {
      my $ruleInst = $gRulePrevInstances{$ruleName} ;

      # if we had a previous match, we compare to it
      if( defined( $result ) ) {
        next if( $result->{STOPLINE} > $ruleInst->{STOPLINE} ) ;
      } #if

      # no previous match, see if this rule passes the test
      # against the controller
      my $isMatch = !defined( $controllingRuleInst ) ;
      if( !$isMatch ) {
        $isMatch = ( $ruleInst->{STARTLINE} > 
          $controllingRuleInst->{STARTLINE} ) ;
      } #if

      # last check: the "controlling rule" can have an
      # instance created for exactly one pre-requisite
      # rule at a time. let's check and see if it's
      # been created...
      if( $isMatch ) {
        if( ${$ruleInst->{RULES_CREATED}}{$controllingRuleName} ) {
          $isMatch = 0 ;
        } #if
      } #if
      $result = $ruleInst if( $isMatch ) ;
    } #if
  } #while

  # indicate we have another winning rule that may create an instance
  if( defined( $result ) ) {
    push( @gWinningRulesForInstanceCreation, $result ) ;
  } #if

  return $result ;
} #LOGENGINE_COMPARE_RULES

# Import the variables from one rule instance into the current instance.
# @param ruleSrc Rule to import from
# @return TRUE (non-zero) upon success, zero upon failure
sub LOGENGINE_IMPORT_INST_VARS {
  # anything to do?
  return 0 if( !defined( $gRuleInstCurrent ) ) ;
  my $rtvarsDest = $gRuleInstCurrent->{RTVARS} ;

  # get vars
  my $ruleSrc = uc( shift ) ;

  # exists?
  return 0 if( !exists( $gRulePrevInstances{$ruleSrc} ) ) ;
  my $ruleSrcInst = $gRulePrevInstances{$ruleSrc} ;

  # do the import (shallow copy)
  my $rtvarsSrc = $ruleSrcInst->{RTVARS} ;
  my $key ;
  foreach $key (keys( %{$rtvarsSrc} )) {
    my $rtvar = ${$rtvarsSrc}{$key} ;
    my $rtvarname = $rtvar->{RULEVAR}->{NAME} ;
    $rtvarsDest->{$rtvarname} = $rtvar ;
  } #foreach
  return 1 ;
} #LOGENGINE_IMPORT_RULE 

# Compare rules (like LOGENGINE_COMPARE_RULES_TO_CONTROLLER)
# *and* perform an instance variable import from the "winning"
# rule.
# @param <...list...> List of rules to compare against the controller
# @return TRUE (non-zero) upon success, zero upon failure
sub LOGENGINE_COMPARE_RULES_AND_IMPORT {
  my $winningInst = LOGENGINE_COMPARE_RULES( (@_ ) ) ;
  return 0 if( !defined( $winningInst ) ) ;
  return LOGENGINE_IMPORT_INST_VARS(
    $winningInst->{RULE}->{FULLNAME} ) ;
} #LOGENGINE_COMPARE_RULES_AND_IMPORT 

# Indicate that the logengine has completed processing
sub LOGENGINE_PROCESSING_COMPLETE {
  $gLogengineQuitFlag = 1 ;
} #LOGENGINE_PROCESSING_COMPLETE 

