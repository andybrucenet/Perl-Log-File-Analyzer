#######################################################################
# debug.pl, ABr, 22MAR00
#
# Debug routines
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

#######################################################################
# GLOBALS

# options
$ABR::gDEBUG = 0 ;
$ABR::gDEBUG_FIRST_TIME = 1 ;
$ABR::gVERBOSE = 0 ;
$ABR::gVERBOSE_FIRST_TIME = 1 ;

sub ABR::verboseprint {
	if ( $ABR::gVERBOSE_FIRST_TIME) {
		$ABR::gVERBOSE_FIRST_TIME = 0 ;
		if (var_is_on("PERL_BLD_VERBOSE")) {
			$ABR::gVERBOSE = 1;
		}
	}
	return if( !$ABR::gVERBOSE ) ;
	foreach my $i ( @_ ) {
		print $i ;
	} #foreach
} #verboseprint

sub ABR::debugprint {
	if ( $ABR::gDEBUG_FIRST_TIME) {
		$ABR::gDEBUG_FIRST_TIME = 0 ;
		if (var_is_on("PERL_BLD_DEBUG")) {
			$ABR::gDEBUG = 1;
		}
	}
	return if( !$ABR::gDEBUG ) ;
	foreach my $i ( @_ ) {
		print $i ;
	} #foreach
} #debugprint


sub var_is_on{
	my ($arg) = @_ ;

	# MKS on NT doesn't always use CAPS for env vars!!
	my $env = $ENV{$arg} ;
	if( !length( $env ) ) {
		$arg = lc( $arg ) ;
		$env = $ENV{$arg} ;
	} #if
	if( !length( $env ) ) {
		$arg = uc( $arg ) ;
		$env = $ENV{$arg} ;
	} #if

	if( $env =~ /Y/ ) {
		return 1;
	}
	return 0;
} #var_is_on

1 ;
