#######################################################################
# utils.pl, ABr, 30MAR00
#
# Generic utilities
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

require "debug.pl" ;

#######################################################################
# Is the passed string a boolean? Allowed input strings can be
# "true", "T", "yes", "Y", <non-zero>, and so on
sub ABR::utils_isTrue {
	my( $str ) = @_ ;

#	debugprint( "Determining boolean truth for '$str'\n" ) ;

	if( defined( $str ) ) {
		if( $str =~ /^[ty].*/i ) {
			return 1 ;
		} elsif( $str =~ /^on$/i ) {
			return 1 ;
		} elsif( $str =~ /^[0-9]+$/ ) {
			return $str != 0 ;
		} #if
	} #if

#	debugprint( "'$str' is *not* a boolean truth!\n" ) ;
	return 0 ;
} #utils_isTrue

#######################################################################
# Extract a value for a particular hash (case insensitive)
# @param \%hash - reference to hash to search
# @param $key - key to use
sub ABR::utils_getHashValue {
	( my $hash, my $key ) = @_ ;
	$key =~ tr/a-z/A-Z/ ;
	return ${%{$hash}}{"$key"} ;
} #utils_getHashValue 

#######################################################################
# Get current time-of-day as a string
sub ABR::utils_getNowTimeString {
	return utils_getTimeString( time() ) ;
} #utils_getNowTimeString

#######################################################################
# Get current date as a string
sub ABR::utils_getNowDateString {
	return utils_getDateString( time() ) ;
} #utils_getNowDateString

#######################################################################
# Get current date time in a string
sub ABR::utils_getNowDateTimeString {
	return utils_getDateTimeString( time() ) ;
} #utils_getNowDateTimeString 

#######################################################################
# Get a time string in format HH:MM:SS
# @param $time - time to interrogate
sub ABR::utils_getTimeString {
	my( $time ) = @_ ;
	my( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
		localtime( $time ) ;
	return sprintf( "%02d:%02d:%02d", $hour, $min, $sec ) ;
} #utils_getTimeString

#######################################################################
# Get a date string in format DD-mmm-YYYY
# @param $time - time to interrogate
sub ABR::utils_getDateString {
	my( $time ) = @_ ;
	my( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
		localtime( $time ) ;
	my $monName = ("Jan","Feb","Mar","Apr","May","Jun",
		"Jul","Aug","Sep","Oct","Nov","Dec")
		[$mon] ;
	return sprintf( "%02d-%s-%04d", $mday, $monName, $year + 1900 ) ;
} #utils_getDateString

#######################################################################
# Get a date/time string based on passed time
sub ABR::utils_getDateTimeString {
	my( $time ) = @_ ;
	return utils_getDateString( $time ) . " " . 
		utils_getTimeString( $time ) ;
} #utils_getDateTimeString 

1 ;

