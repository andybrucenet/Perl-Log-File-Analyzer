@ECHO OFF
REM logengine.bat, Andy Bruce, 6SEP01
REM This batch file exists to invoke the logengine Perl script without
REM requiring the user to specify a -I (include) variable.

perl -Iinclude logengine.pl %*

