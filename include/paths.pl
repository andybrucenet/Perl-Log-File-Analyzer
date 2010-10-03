#######################################################################
# paths.pl, ABr, 22MAR00
#
# Path manipulation functions.
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

require	"os.pl" ;
require "debug.pl" ;

# defines the current TEMP file name
$ABR::paths_CurTempFile = 0 ;

#######################################################################
# this routine makes the slashes correct for the OS and ensures
# that the passed path does *not* end with a slash!
# @param $path - path to check
# @return Fixed result
sub ABR::path_fixPath {
	my( $path ) = @_ ;

	debugprint( "Fixing '$path'..." ) ;

	# fix slashes for OS
	if( $ABR::gOsIsWindows ) {
		# first, check for the CYGWIN pwd stuff
		if( $path=~ /^\/(cygdrive)?\/([A-Za-z])\/(.*)/ ) {
			# cygwin PWD stuff ("/cygdrive/<drive>/<path>")
			$path = $2 . ":/" . $3 ;
		} elsif( $path =~ /^\/\/([A-Za-z])\/(.*)/ ) {
			# bogus "//<drive>/" output by some pwds
			$path = $1 . ":/" . $2 ;
		} #if
		$path =~ s/\//\\/g ;
	} else {
		$path =~ s/\\/\//g ;
	} #if

	# clean out any doubled slashes
	if( $ABR::gOsIsWindows ) {
		$path =~ s/\\\\/\\/g ;
	} else {
		$path =~ s/\/\//\//g ;
	} #if

	# ensure we don't end with a slash
	my $token ;
	if( $ABR::gOsIsWindows ) {
		$token = "\\\\" ;
	} else {
		$token = "\/" ;
	} #if
	my @paths = split( /$token/, $path ) ;
	my $result = "" ;
	my $first = 1 ;
	foreach my $i (@paths) {
		if( $first ) {
			#if( !$ABR::gOsIsWindows ) { $result .= $ABR::gOsSlash ; }
			$first = 0 ;
		} else {
			$result .= $ABR::gOsSlash ;
		} #if
		$result .= $i ;
	} #foreach

	debugprint( "'$result'\n" ) ;

	return $result ;
} #path_fixPath 

#######################################################################
# join a series of path elements to each other properly
# @param \@args - variable length list of args that get joined together,
# 	separated by the OS-specific path separator
# @return Fixed result
sub ABR::path_makePath {
	my $first = 1 ;
	my $result = "" ;
	foreach my $i (@_) {
		# ignore empty args
		if( length( $i ) ) {
			# don't prepend slash for first non-empty arg
			if( $first ) {
				$first = 0 ;
			} else {
				$result .= $ABR::gOsSlash ;
			} #if
			$result .= $i ;
		} #if
	} #foreach
	debugprint( "Made path '$result'\n" ) ;
	return $result ;
} #path_makePath 

#######################################################################
# Extract the filename portion of a pathspec
# @param $path - path to analyze
# @return Filename of the pathspec
sub ABR::path_extractFname {
	my( $path ) = @_ ;

	# find last occurrence of path sep
	my $idx = rindex( $path, "/") ;
	$idx = rindex( $path, "\\") if( $idx < 0 );
	return $path if( $idx < 0 ) ;

	# return it
	return substr( $path, $idx + 1 ) ;
} #path_extractFname

#######################################################################
# Extract the path portion of a pathspec
# @param $path - path to analyze
# @return Path of the pathspec
sub ABR::path_extractPath {
	my( $path ) = @_ ;

	# find last occurrence of path sep
	my $idx = rindex( $path, "/") ;
	$idx = rindex( $path, "\\") if( $idx < 0 );
	return $path if( $idx < 0 ) ;

	# return it
	return substr( $path, 0, $idx ) ;
} #path_extractFname

#######################################################################
# create a subdirectory, including all parents
# @param $path - path to create
# @return Zero upon success
sub ABR::path_mkdirs {
	my $path = $_[0] ;

	# ensure we don't end with a slash
	my $token ;
	if( $ABR::gOsIsWindows ) {
		$token = "\\\\" ;
	} else {
		$token = "\/" ;
	} #if
	my @paths = split( /$token/, $path ) ;
	my $dir = "" ;
	my $first = 1 ;
	foreach my $i (@paths) {
		if( $first ) {
			if( !$ABR::gOsIsWindows ) { $dir .= $ABR::gOsSlash ; }
			$first = 0 ;
		} else {
			$dir .= $ABR::gOsSlash ;
		} #if
		$dir .= $i ;
		if( length( $dir ) ) {
			if( !( -e $dir ) ) {
				if( !mkdir( $dir, 0777 ) ) {
					print( "Cannot create directory '$dir': $!\n" ) ;
					return 1 ; 
				} #if
			} #if
		} #if
	} #foreach

	return 0 ;
} #path_mkdirs

#######################################################################
# Extract the DIRECTORY portion of a path
# @param $path - path to analyze
# @return Scalar containing the directory name *with* the trailing
#	slash ("./" if not specified). This directory name has already
#	been "cooked" to be correct for the operating system.
sub ABR::path_getPath {
	my( $path ) = @_ ;

	# first, normalize the path
	my $fixedPath = ABR::path_fixPath( $path ) ;

	# second, look for the last path separator
	my $pos = rindex( $fixedPath, "/") ;
	$pos = rindex( $fixedPath, "\\") if( $pos < 0);

	# if not found, return "."
	if( $pos < 0 ) { return "." . $ABR::gOsSlash ; }

	# return the string
	return substr( $fixedPath, 0, $pos + 1 ) ;
} #path_getPath 

#######################################################################
# Extract the FILE portion of a path
# @param $path - path to analyze
# @return Scalar containing the file name.
sub ABR::path_getFile {
	my( $path ) = @_ ;

	# first, normalize the path
	my $fixedPath = ABR::path_fixPath( $path ) ;

	# second, look for the last path separator
	my $pos = rindex( $fixedPath, "/") ;
	$pos = rindex( $fixedPath, "\\") if( $pos < 0);

	# if not found, return empty string
	if( $pos < 0 ) { return "" ; }

	# return the string
	return substr( $fixedPath, $pos + 1 ) ;
} #path_getFile 

#######################################################################
# Copy a file to another file, without using any OS commands
# @param $src - source file
# @param $dest - destination file
# @return Zero upon success
sub ABR::path_cpFile {
	my( $src, $dest ) = @_ ;

	# access files
	if( !sysopen( SRC, $src, 0 ) ) {
		print "ABR::path_cpFile: Error opening SRC '$src': $!\n" ;
		return 1 ;
	} #if
	if( !open( DEST, ">$dest" ) ) {
		print "ABR::path_cpFile: Error opening DEST '$dest': $!\n" ;
		close SRC ;
		return 1 ;
	} #if
	close DEST ;
	if( !sysopen( DEST, "$dest", 1 ) ) {
		print "ABR::path_cpFile: Error opening DEST '$dest': $!\n" ;
		close SRC ;
		return 1 ;
	} #if

	binmode SRC ;
	binmode DEST ;

	# copy file
	my $buff, my $len ;
	while( $len = sysread( SRC, $buff, 4096 ) ) {
		my $offset = 0 ;
		while( $len ) {
			my $written = syswrite( DEST, $buff, $len, $offset ) ;
			die( "ABR::path_cpFile: Error writing to '$dest': $!\n" )
				unless defined $written ;
			$len -= $written ;
			$offset += $written ;
		} #while
	} #while

	# done with files
    close SRC ;
    close DEST ;

    # it worked
    return 0 ;
} #path_cpFile 

#######################################################################
# Load a text file to a string variable.
# @param $src - file to read
# @return Scalar variable containing file data.
sub ABR::path_readFile {
	my( $file ) = @_ ;

	# access
	if( !open( FILE, $file ) ) {
		print( "ABR::path_readFile: Error opening file '$file': $!\n" ) ;
		return ;
	} #if

	# read the file
	my $lines ;
	while( my $line = <FILE> ) {
		$lines .= $line ;
	} #while

	# done
	close FILE ;
	return $lines ;
} #ABR::gPATHS_IPL_DEFINED

#######################################################################
# Store a string variable to a text file
# @param $src - file to write
# @param $lines - Scalar variable containing file data.
# @return Non-zero on error
sub ABR::path_writeFile {
	my( $file, $lines ) = @_ ;

	# access
	if( !open( FILE, ">$file" ) ) {
		print( "ABR::path_writeFile: Error opening file '$file': $!\n" ) ;
		return ;
	} #if

	# write the file
	print FILE $lines ;

	# done
	close FILE ;
	return 0 ;
} #path_writeFile

#######################################################################
# Load a complete directory structure without using os commands.
# @param $dir - starting directory
# @param $spec - file spec to find
# @param $recurse - TRUE if we should recurse directories
# @return List of file names (full file path!)
sub ABR::path_readDirSpec {
	my( $dir, $spec, $recurse ) = @_ ;

	# load up for the big load!
	$dir = path_fixPath( $dir ) ;
	chomp( my $pwd = os_execBacktickCmd( "pwd" ) ) ;
	chdir( $dir ) ;

	# read the entries
	my @result ; 
	path_readDirSpecInternal( $dir, $spec, $recurse, \@result ) ;

	# change back to original directory
	chdir( $pwd ) ;
	return @result ;
} #path_readDirSpec

sub ABR::path_readDirSpecInternal {
	my( $dir, $spec, $recurse, $refResult ) = @_ ;

	chdir( $dir ) ;

	# open the directory and read all files matching filespec
	my @files = glob( $spec ) ;
	my $file ;
	foreach $file (@files) {
		last if( $file =~ /^(\.|\.\.)$/ ) ;
		my $fullPath = path_makePath( $dir, $file ) ;
		push( @$refResult, $fullPath ) ;
	} #foreach

	# now we glob *all* files, and get the directories in a list
	my @dirs ;
	if( utils_isTrue( $recurse ) ) {
		@files = glob( "*" ) ;
		foreach $file (@files) {
			last if( $file =~ /^(\.|\.\.)$/ ) ;
			my $fullPath = path_makePath( $dir, $file ) ;
			if( -d $fullPath ) {
				push( @dirs, $fullPath ) ;
			} #if
		} #foreach
	} #if

	# recurse if necessary
	my $dir ;
	foreach $dir (@dirs) {
		path_readDirSpecInternal( $dir, $spec, $recurse, $refResult ) ;
	} #foreach
} #path_readDirSpecInternal 

#######################################################################
# Create a temporary file in the named directory, with the named
# prefix.
# @param strPrefix - if undefined, defaults to "TMP"
# @param strExt - if undefined, defaults to ".TMP"
# @param strDir - if undefined, defaults to "."
sub path_makeTempFile {
	my( $strPrefix, $strExt, $strDir ) = @_ ;
	$strPrefix = "TMP" if( !defined( $strPrefix ) ) ;
	$strExt = ".TMP" if( !defined( $strExt ) ) ;
	$strDir = "." if( !defined( $strDir ) ) ;

	# create the temp dir
	my $fullPrefix = path_makePath( $strDir, "$strPrefix" ) ;
	debugprint ("makeTempFile: fullPrefix='$fullPrefix'\n") ;

	# attempt to locate a file
	my( $continue, $result ) ;
	$continue = 1, $result = "" ;
	while( $continue ) {
		my $fileName = sprintf( "%s%05d%s",
			$fullPrefix, $ABR::paths_CurTempFile, $strExt ) ;
		debugprint ("makeTempFile: fileName='$fileName'\n") ;
		++$ABR::paths_CurTempFile ;
		$continue = ( -f $fileName ) ;
		if( !$continue ) {
			$continue = !open( PATHS_TEMP_FILE, ">$fileName" ) ;
			if( !$continue ) {
				$result = $fileName ;
				close PATHS_TEMP_FILE ;
			} #if
		} #if
	} #while

	return $result ;
} #path_makeTempFile

1 ;

