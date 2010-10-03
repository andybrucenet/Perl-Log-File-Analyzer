#######################################################################
# os.pl, ABr, 22MAR00
#
# OS variables and routines
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

package ABR ;

use strict ;

# hacks to make sure that output works!
use FileHandle ;
autoflush STDOUT 1 ;

#######################################################################
# GLOBALS

# OS vars
$ABR::gOsIsWindows = 0 ;
$ABR::gOsPathSep = ":" ;
$ABR::gOsSlash = "/" ;
$ABR::gOsCopy = "cp " ;
$ABR::gOsQuiet = "" ;
$ABR::gOsTar = " */* " ;
$ABR::gOsPath = $ENV{PATH} ;
$ABR::gOsNull = "/dev/null" ;

#######################################################################
# setup global parms and so on
sub ABR::os_setup {
	my $windir = ABR::os_getenv( "WINDIR" ) ;
	if( !length( $windir ) ) {
		$windir = ABR::os_getenv( "ComSpec" ) ;
	} #if
	if( length( $windir ) ) {
		$ABR::gOsIsWindows = 1 ;
		$ABR::gOsPathSep = ";" ;
		$ABR::gOsSlash = "\\" ;
		$ABR::gOsCopy = "xcopy " ;
		$ABR::gOsQuiet = " /q " ;
		$ABR::gOsTar = " * " ;
		$ABR::gOsNull = "NUL" ;
	} #if
} #os_setup

sub ABR::os_getUname {
	# first, get the name from the OS
	my $uname ;
	chomp( $uname = os_execBacktickCmd( "uname -s" ) ) ;

	# HACK for Cygwin
	if( $uname =~ /CYGWIN_NT/i ) {
		$uname = "Windows_NT" ;
	} #if

	# another HACK that must occur (so far) only for
	# certain scripts running under CYGWIN 
	if( !length( $uname ) ) {
		$uname = "Windows_NT" ;
	} #if

	return $uname ;
} #os_getUname

# Get an environment variable, accounting for goofy MKS logic
sub ABR::os_getenv {
	my ($var) = @_ ;

	# check the proper thing
	my $result = $ENV{$var} ;
	$result = "" if( !defined( $result ) ) ;

	# MKS sometimes lower-cases ENV vars
	if( !length( $result ) ) {
		$var = lc( $var ) ;
		$result = $ENV{$var} ;
		$result = "" if( !defined( $result ) ) ;
	} #if

	# for safety, let's also uppercase
	if( !length( $result ) ) {
		$var = uc( $var ) ;
		$result = $ENV{$var} ;
	} #if

	return $result ;
} #os_getenv

sub ABR::os_execBacktickCmd {
	my( $cmd ) = @_ ;

	# first, try to exec the command
	my $results ;
	chomp( $results = `$cmd` ) ;
	if( !length( $results ) ) {
		# let's try it another way!
		system( "$cmd >out.txt" ) ;
		if( open( F_EXEC_CMD, "out.txt" ) ) {
			my $line ;
			while( $line = <F_EXEC_CMD> ) {
				$results .= $line ;
			} #while
			close F_EXEC_CMD ;
			system( "rm out.txt" ) ;

			# remove the *last* trailing newline from result
			chomp( $results ) ;
		} #if
	} #if

	# return results
	return $results ;
} #os_execBacktickCmd

1 ;
