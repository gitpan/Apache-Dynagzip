package Apache::Dynagzip;

use 5.004;
use strict;
use Apache::Constants qw(:response :methods :http);
use Compress::LeadingBlankSpaces;
use Compress::Zlib 1.16;
use Apache::File;
use Apache::Log ();
use Apache::URI();
use Apache::Util;
use Fcntl qw(:flock);
use FileHandle;

use vars qw($VERSION $BUFFERSIZE %ENV);
$VERSION = "0.08";
$BUFFERSIZE = 16384;
use constant MAGIC1	=> 0x1f ;
use constant MAGIC2	=> 0x8b ;
use constant OSCODE	=> 3 ;
use constant MIN_HDR_SIZE => 10 ; # minimum gzip header size
use constant MIN_CHUNK_SIZE_DEFAULT => 8;            # when gzip only
use constant MIN_CHUNK_SIZE_SOURCE_DEFAULT => 32768; # when gzip only
use constant CHUNK_PARTIAL_FLUSH_DEFAULT => 'On';
use constant MIN_CHUNK_SIZE_PP_DEFAULT => 8192;      # for no gzip case
use constant MAX_ATTEMPTS_TO_TRY_FLOCK => 10;  # max limit seconds to sleep, waiting for flock()
use constant PAGE_LIFE_TIME_DEFAULT    => 300; # sec

sub can_gzip_for_this_client {
	# This is the only place where I decide whether or not the main request of the client
	# could be served with gzip compression.
	# call model: my $can_gzip = can_gzip_for_this_client($r);
	my $r = shift;
	my $result = undef; # false is default
	if ($r->header_in('Accept-Encoding') =~ /gzip/){
		$result = 1; # true
	}
	# All known exceptions should go in here...
	#
	return $result;
}
sub retrieve_all_cgi_headers_via { # call model: my $hdrs = retrieve_all_cgi_headers_via ($fh);
	my $fh = shift;
	my $headers;
	{
		local $/ = "\n\n";
		$headers = <$fh>;
	}
	return $headers;
}
sub send_lightly_compressed_stream { # call model: send_lightly_compressed_stream($r, $fh);
	# Transfer the stream from filehandle $fh to standard output
	# using "blank-space compression only...
	#
	my $r = shift;
	my $fh = shift;
	my $body = ''; # incoming content
	my $buf;
	my $lbr = Compress::LeadingBlankSpaces->new();
	while (defined($buf = <$fh>)){
		if ($buf = $lbr->squeeze_string ($buf)) {
			$body .= $buf;
			print ($buf);
		}
	}
	return $body;
}
sub send_lightly_compressed_stream_chunked { # call model: send_lightly_compressed_stream_chunked($r, $fh, $minChSize);
	# Transfer the stream chunked from filehandle $fh to standard output
	# using "blank-space compression only...
	#
	my $r = shift;
	my $fh = shift;
	my $minChunkSizePP = shift;
	my $body = ''; # incoming content
	my $buf;
	my $chunkBody = '';
	my $lbr = Compress::LeadingBlankSpaces->new();

	while (defined($buf = <$fh>)){
		$buf = $lbr->squeeze_string ($buf);
		if (length($buf) > 0){
			$chunkBody .= $buf;
		}
		if (length($chunkBody) > $minChunkSizePP){ # send it...
			$body .= $chunkBody;
			print (chunk_out($chunkBody));
			$chunkBody = '';
		}
	}
	if (length($chunkBody) > 0){ # send it...
		$body .= $chunkBody;
		print (chunk_out($chunkBody));
		$chunkBody = '';
	}
	return $body;
}
sub chunkable { # call model: $var = chunkable($r);
	# Check if the response could be chunked
	#
	my $r = shift;
	my $result = undef;
	if ($r->protocol =~ /http\/1\.(\d+)/io) {
		# any HTTP/1.X is OK, just X==0 will be evaluated to FALSE in result
		$result = $1;
	}
	return $result;
}
sub chunk_out { # call model: my $chunk = chunk_out ($string);
	my $HttpEol = "\015\012";  # HTTP end of line marker (see RFC 2068)
	my $source = shift;
	return  sprintf("%x",length($source)).$HttpEol.$source.$HttpEol;
}
sub kill_over_env { # just to clean up the unnessessary environment
	delete($ENV{HISTSIZE});
	delete($ENV{HOSTNAME});
	delete($ENV{LOGNAME});
	delete($ENV{HISTFILESIZE});
	delete($ENV{SSH_TTY});
	delete($ENV{MAIL});
	delete($ENV{MACHTYPE});
	delete($ENV{TERM});
	delete($ENV{HOSTTYPE});
	delete($ENV{OLDPWD});
	delete($ENV{HOME});
	delete($ENV{INPUTRC});
	delete($ENV{SUDO_GID});
	delete($ENV{SHELL});
	delete($ENV{SUDO_UID});
	delete($ENV{USER});
	delete($ENV{SUDO_USER});
	delete($ENV{SSH_CLIENT});
	delete($ENV{OSTYPE});
	delete($ENV{PWD});
	delete($ENV{SHLVL});
	delete($ENV{SUDO_COMMAND});
	delete($ENV{_});
	delete($ENV{HTTP_CONNECTION});
}
sub cgi_headers_from_script { # call model: my $condition = cgi_headers_from_script($r);
	my $r = shift;
	my $res = lc $r->dir_config('UseCGIHeadersFromScript') eq 'on';
	return $res;
}

sub handler { # it is supposed to be only a dispatcher since now...

	my $r = shift;
	my $HttpEol = "\015\012";  # HTTP end of line marker (see RFC 2068)
	my $fh = undef; # will be the reference to the incoming data stream

	my $qualifiedName = join(' ', __PACKAGE__, 'default_content_handler');

	# make sure to dispatch the request appropriately:
	# I serve Perl & Java streams through the Apache::Filter Chain only.
	my $filter = lc $r->dir_config('Filter') eq 'on';
	my $binaryCGI = undef; # It might be On when Filter is Off ONLY.
	unless ($filter){
		$binaryCGI = lc $r->dir_config('BinaryCGI') eq 'on';
	}
	# I assume the Light Compression Off as default:
	my $light_compression = lc $r->dir_config('LightCompression') eq 'on';

	# There are no way to compress and/or chunk the response to internally redirected request.
	# No safe support could be provided for the server-side caching in this case.
	# No way to send back the Content-Length even when one exists for the plain file...
	# Just send back the content assuming it is text/html (or whatever is declared by the main response):
	unless ($r->is_main){
		# bad luck this time...
		# No control over the HTTP headers:
		my $message = ' No control over the chunks is provided. Light Compression is ';
		if ($light_compression) {
			$message .= 'On.';
		} else {
			$message .= 'Off.';
		}
		$message .= ' Source comes from ';
		if ($filter) {
			$message .= 'Filter Chain.';
		} elsif ($binaryCGI) {
			$message .= 'Binary CGI.';
		} else {
			$message .= 'Plain File.';
		}
		$r->log->warn($qualifiedName.' is serving the redirected request for '.$r->the_request
			.' targeting '.$r->filename.' via '.$r->uri.$message);

		if ($filter) {
			# make filter-chain item with no chunks...
			$r = $r->filter_register;
			$fh = $r->filter_input();
			unless ($fh){
				my $message = ' Fails to obtain the Filter data handle for ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return SERVER_ERROR;
			}
			my $headers = retrieve_all_cgi_headers_via ($fh);
			$r->send_cgi_header($headers); # just for the case...
			if ($r->header_only){
				$r->log->warn($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
				return OK;
			}
			if ($light_compression) {
				send_lightly_compressed_stream($r, $fh);
			} else { # no light compression
				while (<$fh>) {
					print ($_);
				}
			}
			$r->log->warn($qualifiedName.' is done OK for '.$r->the_request);
			return OK;
		} # if ($filter)

		unless ($binaryCGI) { # Transfer a Plain File responding to redirected request

			unless (-e $r->finfo){
				$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
				return NOT_FOUND;
			}
			if ($r->method_number != M_GET){
				my $message = ' is not allowed for redirected request targeting ';
				$r->log->error($qualifiedName.' aborts: '.$r->method.$message.$r->filename);
				return HTTP_METHOD_NOT_ALLOWED;
			}
			unless ($fh = Apache::File->new($r->filename)){
				my $message = ' file permissions deny server access to ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return FORBIDDEN;
			}
			# since the file is opened successfully, I need to flock() it...
			my $success = 0;
			my $tries = 0;
			while ($tries++ < MAX_ATTEMPTS_TO_TRY_FLOCK){
				last if $success = flock ($fh, LOCK_SH|LOCK_NB);
				$r->log->warn($qualifiedName.' is waiting for read flock of '.$r->filename);
				sleep (1); # wait a second...
			}
			unless ($success){
				$fh->close;
				$r->log->error($qualifiedName.' aborts: Fails to obtain flock on '.$r->filename);
				return SERVER_ERROR;
			}
			# I send no HTTP headers here just for case...
			if ($light_compression) {
				send_lightly_compressed_stream($r, $fh);
			} else { # no light compression
				$r->send_fd($fh);
			}
			$fh->close;
			$r->log->warn($qualifiedName.' is done OK for '.$r->the_request);
			return OK;
		} # unless ($binaryCGI)

		# It is Binary CGI to transfer:

		# double-check the target file's existance and access permissions:
		unless (-e $r->finfo){
			$r->log->error($qualifiedName.' aborts: File does not exist: '.$r->filename);
			return NOT_FOUND;
		}
		my $filename = $r->filename();
		unless (-f $filename and -x _ ) {
			$r->log->error($qualifiedName.' aborts: no exec permissions for '.$r->filename);
			return SERVER_ERROR;
		}
		$r->chdir_file();

		# make %ENV appropriately:
		my $gwi = 'CGI/1.1';
		$ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		if ($r->method eq 'POST'){ # it NEVER has notes...
			# POST features:
			# since the stdin has a broken structure when passed through the perl-UNIX-pipe
			# I emulate the appropriate GET request to the pp-binary...
			delete($ENV{CONTENT_LENGTH});
			delete($ENV{CONTENT_TYPE});
			my $content = $r->content;
			$ENV{QUERY_STRING} = $content;
			$ENV{REQUEST_METHOD} = 'GET';
		}
		unless ($fh = FileHandle->new("$filename |")) {
			$r->log->error($qualifiedName.' aborts: Fails to obtain incoming data handle for '.$r->filename);
			return NOT_FOUND;
		}
		# lucky to proceed:
		my $headers = retrieve_all_cgi_headers_via ($fh);
		$r->send_cgi_header($headers);
		if ($r->header_only){
			$fh->close;
			$r->log->warn($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
			return OK;
		}
		if ($light_compression) {
			local $\;
			send_lightly_compressed_stream($r, $fh);
		} else { # no any compression:
			local $\;
			while (<$fh>) {
				print ($_);
			}
		}
		$fh->close;
		$r->log->warn($qualifiedName.' is done OK for '.$r->the_request);
		return OK;
	} # unless ($r->is_main)
	
	# This is the main request,
	# =========================
	# check if it worths to gzip for the client:
	my $can_gzip = can_gzip_for_this_client($r);

	my $message = ' Light Compression is ';
	if ($light_compression) {
		$message .= 'On.';
	} else {
		$message .= 'Off.';
	}
	$message .= ' Source comes from ';
	if ($filter) {
		$message .= 'Filter Chain.';
	} elsif ($binaryCGI) {
		$message .= 'Binary CGI.';
	} else {
		$message .= 'Plain File.';
	}
	$message .= ' The client '.$r->header_in("User-agent");
	if ($can_gzip){
		$message .= ' accepts GZIP.';
	} else {
		$message .= ' does not accept GZIP.';
	}
	$r->log->info($qualifiedName.' is serving the main request for '.$r->the_request
		.' targeting '.$r->filename.' via '.$r->uri.$message);
	$r->header_out("X-Module-Sender" => __PACKAGE__);

	# Client Local Cache Control (see rfc2068):
	# The Expires entity-header field gives the date/time after which the response should be considered stale.
	# A stale cache entry may not normally be returned by a cache (either a proxy cache or an user agent cache)
	# unless it is first validated with the origin server (or with an intermediate cache that has a fresh copy
	# of the entity). The format is an absolute date and time as defined by HTTP-date in section 3.3;
	# it MUST be in RFC1123-date format: Expires = "Expires" ":" HTTP-date
	my $life_length = $r->dir_config('pageLifeTime') || PAGE_LIFE_TIME_DEFAULT;
	my $now = time() + $life_length;
	my $time_format_gmt = '%A, %d-%B-%Y %H:%M:%S %Z';
	my $date_gmt = Apache::Util::ht_time($now, $time_format_gmt);
	$r->header_out("Expires" => $date_gmt);

	# Advanced control over the client/proxy Cache:
	#
	my $extra_vary = $r->dir_config('Vary');
	my $current_vary = $r->header_out("Vary");
	my $new_vary = join (',',$current_vary,$extra_vary);
	$r->header_out("Vary" => $new_vary) if $extra_vary;

my $can_chunk = chunkable($r); # check if it is HTTP/1.1 or higher
unless ($can_chunk) {
	# No chunks for HTTP/1.0. Close connection instead...
	$r->header_out('Connection','close'); # for HTTP/1.0
	$r->log->debug($qualifiedName.' is serving the main request in no-chunk mode for '.$r->the_request);
	unless ($can_gzip) { # send plain content
		# server-side cache control might be in effect, if ordered...
		$r->log->info($qualifiedName.' no gzip for '.$r->the_request);
		if ($filter) {
			# create the filter-chain with no chunks...
			$r = $r->filter_register;
			$fh = $r->filter_input();
			unless ($fh){
				my $message = ' Fails to obtain the Filter data handle for ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return SERVER_ERROR;
			}
			my $headers = retrieve_all_cgi_headers_via ($fh);
			$r->send_cgi_header($headers); # just for the case...
			if ($r->header_only){
				my $message = ' request for HTTP header only is done OK for ';
				$r->log->info($qualifiedName.$message.$r->the_request);
				return OK;
			}
			my $body = ''; # incoming content
			if ($light_compression) {
				$body = send_lightly_compressed_stream($r, $fh);
			} else { # no light compression
				while (<$fh>) {
					$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
					# to create the effective compression within the later stage,
					# when the caching is ordered...
					print ($_);
				}
			}
			if ($r->notes('ref_cache_files')){
				$r->notes('ref_source' => \$body);
				$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
			}
			$r->log->info($qualifiedName.' is done OK for '.$r->filename);
			return OK;
		} # if ($filter)

		unless ($binaryCGI) { # Transfer a Plain File responding to the main request

			unless (-e $r->finfo){
				$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
				return NOT_FOUND;
			}
			if ($r->method_number != M_GET){
				my $message = ' is not allowed for request targeting ';
				$r->log->error($qualifiedName.' aborts: '.$r->method.$message.$r->filename);
				return HTTP_METHOD_NOT_ALLOWED;
			}
			unless ($fh = Apache::File->new($r->filename)){
				my $message = ' file permissions deny server access to ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return FORBIDDEN;
			}
			# since the file is opened successfully, I need to flock() it...
			my $success = 0;
			my $tries = 0;
			while ($tries++ < MAX_ATTEMPTS_TO_TRY_FLOCK){
				last if $success = flock ($fh, LOCK_SH|LOCK_NB);
				$r->log->warn($qualifiedName.' is waiting for read flock of '.$r->filename);
				sleep (1); # wait a second...
			}
			unless ($success){
				$fh->close;
				$r->log->error($qualifiedName.' aborts: Fails to obtain flock on '.$r->filename);
				return SERVER_ERROR;
			}
			$r->send_http_header;
			if ($r->header_only){
				$r->log->info($qualifiedName.' request for header only is OK for ', $r->filename);
				return OK;
			}
			my $body = ''; # incoming content
			if ($light_compression) {
				$body = send_lightly_compressed_stream($r, $fh);
			} else { # no light compression
				while (<$fh>) {
					$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
					# to create the effective compression within the later stage,
					# when the caching is ordered...
					print ($_);
				}
			}
			$fh->close;

			if ($r->notes('ref_cache_files')){
				$r->notes('ref_source' => \$body);
				$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
			}
			$r->log->warn($qualifiedName.' is done OK for '.$r->the_request.' targeted '.$r->filename);
			return OK;
		} # unless ($binaryCGI)

		# It is Binary CGI to transfer with no gzip compression:
		#
		# double-check the target file's existance and access permissions:
		unless (-e $r->finfo){
			$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
			return NOT_FOUND;
		}
		my $filename = $r->filename();
		unless (-f $filename and -x _ ) {
			$r->log->error($qualifiedName.' aborts: no exec permissions for '.$r->filename);
			return SERVER_ERROR;
		}
		$r->chdir_file();

		# make %ENV appropriately:
		my $gwi = 'CGI/1.1';
		$ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		if ($r->method eq 'POST'){ # it NEVER has notes...
			# POST features:
			# since the stdin has a broken structure when passed through the perl-UNIX-pipe
			# I emulate the appropriate GET request to the pp-binary...
			delete($ENV{CONTENT_LENGTH});
			delete($ENV{CONTENT_TYPE});
			my $content = $r->content;
			$ENV{QUERY_STRING} = $content;
			$ENV{REQUEST_METHOD} = 'GET';
		}
		unless ($fh = FileHandle->new("$filename |")) {
			$r->log->error($qualifiedName.' aborts: Fails to obtain incoming data handle for '.$r->filename);
			return NOT_FOUND;
		}
		# lucky to proceed:
		my $headers = retrieve_all_cgi_headers_via ($fh);
		$r->send_cgi_header($headers);
		if ($r->header_only){
			$fh->close;
			$r->log->warn($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
			return OK;
		}
		my $body = ''; # incoming content
		if ($light_compression) {
			local $\;
			$body = send_lightly_compressed_stream($r, $fh);
		} else { # no any compression, just chunked:
			local $\;
			my $chunkBody = '';
			while (<$fh>) {
				$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
				# to create the effective compression within the later stage,
				# when the caching is ordered...
				print ($_);
			}
		}
		$fh->close;

		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->info($qualifiedName.' is done OK for '.$r->the_request);
		return OK;

	} # unless ($can_gzip)

	# Can gzip with no chunks:
	$r->content_encoding('gzip');
	$r->header_out('Vary','Accept-Encoding');

	# retrieve settings from config:
	my $minChunkSize = $r->dir_config('minChunkSize') || MIN_CHUNK_SIZE_DEFAULT;
	my $minChunkSizeSource = $r->dir_config('minChunkSizeSource') || MIN_CHUNK_SIZE_SOURCE_DEFAULT;

	if ($filter) {
		$r = $r->filter_register;
		$fh = $r->filter_input();
		unless ($fh){
			my $message = ' Fails to obtain the Filter data handle for ';
			$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
			return SERVER_ERROR;
		}
		if (cgi_headers_from_script($r)) {
			my $headers = retrieve_all_cgi_headers_via ($fh);
			$r->log->debug($qualifiedName.' has CGI-header(s): '.$headers.' from '.$r->filename);
			$r->send_cgi_header($headers);
		} else { # create the own set of HTTP headers:
			$r->log->debug($qualifiedName.' creates own HTTP headers for '.$r->the_request);
			$r->content_type("text/html");
			$r->send_http_header;
		}
		if ($r->header_only){
			$r->log->info($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
			return OK;
		}
		my $body = ''; # incoming content
		# Create the deflation stream:
		my ($gzip_handler, $status) = deflateInit(
		     -Level      => Z_BEST_COMPRESSION(),
		     -WindowBits => - MAX_WBITS(),);
		unless ($status == Z_OK()){ # log the Error:
			my $message = 'Cannot create a deflation stream. ';
			$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
			return SERVER_ERROR;
		}
		# Create the first outgoing portion of the content:
		my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
		my $chunkBody = $gzipHeader; # this is just a portion to output this times...

		my $partialSourceLength = 0;	# the length of the source
						# associated with the portion gzipped in current chunk
		my $lbr = Compress::LeadingBlankSpaces->new();
		while (<$fh>) {
			$_ = $lbr->squeeze_string($_) if $light_compression;
			my $localPartialFlush = 0; # should be false default inside this loop
			$body .= $_; # accumulate all here to create the effective compression
				     # within the cleanup stage, when the caching is ordered...
			$partialSourceLength += length($_); # to deside if the partial flush is required
			if ($partialSourceLength > $minChunkSizeSource){
				$localPartialFlush = 1; # just true
				$partialSourceLength = 0; # for the next pass
			}
			my ($out, $status) = $gzip_handler->deflate(\$_);
			if ($status == Z_OK){
				$chunkBody .= $out; # it may bring nothing indeed...
				$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
			} else { # log the Error:
				$gzip_handler = undef; # clean it up...
				my $message = 'Cannot gzip the Current Section. ';
				$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
				return SERVER_ERROR;
			}
			if (length($chunkBody) > $minChunkSize ){ # send it...
				print ($chunkBody);
				$chunkBody = ''; # for the next iteration
			}
		}
		$chunkBody .= $gzip_handler->flush();
		$gzip_handler = undef; # clean it up...
		# Append the checksum:
		$chunkBody .= pack("V V", crc32(\$body), length($body));
		print ($chunkBody);
		$chunkBody = '';

		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->info($qualifiedName.' is done OK for '.$r->filename);
		return OK;
	} # if ($filter)

	unless ($binaryCGI) { # Transfer a Plain File gzipped, responding to the main request

		unless (-e $r->finfo){
			$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
			return NOT_FOUND;
		}
		if ($r->method_number != M_GET){
			my $message = ' is not allowed for redirected request targeting ';
			$r->log->error($qualifiedName.' aborts: '.$r->method.$message.$r->filename);
			return HTTP_METHOD_NOT_ALLOWED;
		}
		unless ($fh = Apache::File->new($r->filename)){
			my $message = ' file permissions deny server access to ';
			$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
			return FORBIDDEN;
		}
		# since the file is opened successfully, I need to flock() it...
		my $success = 0;
		my $tries = 0;
		while ($tries++ < MAX_ATTEMPTS_TO_TRY_FLOCK){
			last if $success = flock ($fh, LOCK_SH|LOCK_NB);
			$r->log->warn($qualifiedName.' is waiting for read flock of '.$r->filename);
			sleep (1); # wait a second...
		}
		unless ($success){
			$fh->close;
			$r->log->error($qualifiedName.' aborts: Fails to obtain flock on '.$r->filename);
			return SERVER_ERROR;
		}
#		$r->content_type("text/html");
		$r->send_http_header;
		if ($r->header_only){
			$r->log->info($qualifiedName.' request for header only is OK for ', $r->filename);
			return OK;
		}
		# Create the deflation stream:
		my ($gzip_handler, $status) = deflateInit(
		     -Level      => Z_BEST_COMPRESSION(),
		     -WindowBits => - MAX_WBITS(),);
		unless ($status == Z_OK()){ # log the Error:
			$fh->close; # and unlock...
			my $message = 'Cannot create a deflation stream. ';
			$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
			return SERVER_ERROR;
		}
		# Create the first outgoing portion of the content:
		my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
		my $chunkBody = $gzipHeader;

		my $body = ''; # incoming content
		my $partialSourceLength = 0; # the length of the source associated with the portion gzipped in current chunk
		my $lbr = Compress::LeadingBlankSpaces->new();
		while (<$fh>) {
			$_ = $lbr->squeeze_string($_) if $light_compression;
			my $localPartialFlush = 0; # should be false default inside this loop
			$body .= $_;    # accumulate all here to create the effective compression within the cleanup stage,
					# when the caching is ordered...
			$partialSourceLength += length($_); # to deside if the partial flush is required
			if ($partialSourceLength > $minChunkSizeSource){
				$localPartialFlush = 1; # just true
				$partialSourceLength = 0; # for the next pass
			}
			my ($out, $status) = $gzip_handler->deflate(\$_);
			if ($status == Z_OK){
				$chunkBody .= $out; # it may bring nothing indeed...
				$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
			} else { # log the Error:
				$fh->close; # and unlock...
				$gzip_handler = undef; # clean it up...
				my $message = 'Cannot gzip the Current Section. ';
				$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
				return SERVER_ERROR;
			}
			if (length($chunkBody) > $minChunkSize ){ # send it...
				print ($chunkBody);
				$chunkBody = ''; # for the next iteration
			}
		}
		$fh->close; # and unlock...
		$chunkBody .= $gzip_handler->flush();
		$gzip_handler = undef; # clean it up...
		# Append the checksum:
		$chunkBody .= pack("V V", crc32(\$body), length($body)) ;
		print ($chunkBody);
		$chunkBody = '';
		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->info($qualifiedName.' is done OK for '.$r->filename);
		return OK;
	} # unless ($binaryCGI)

	# It is Binary CGI to transfer with gzip compression:
	#
	# double-check the target file's existance and access permissions:
	unless (-e $r->finfo){
		$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
		return NOT_FOUND;
	}
	my $filename = $r->filename();
	unless (-f $filename and -x _ ) {
		$r->log->error($qualifiedName.' aborts: no exec permissions for '.$r->filename);
		return SERVER_ERROR;
	}
	$r->chdir_file();

	# make %ENV appropriately:
	if ($r->notes('PP_PATH_TRANSLATED')){
		$r->log->info($qualifiedName.' has notes: PP_PATH_TRANSLATED='.$r->notes('PP_PATH_TRANSLATED'));
		my $gwi = 'CGI/1.1';
		$ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		$ENV{QUERY_STRING} = $r->notes('PP_QUERY_STRING');
		$ENV{SCRIPT_NAME} = $r->notes('PP_SCRIPT_NAME');
		$ENV{DOCUMENT_NAME}='index.html';
		$ENV{DOCUMENT_PATH_INFO}='';

		$ENV{REQUEST_URI} = $ENV{SCRIPT_NAME}.'?'.$ENV{QUERY_STRING};
		$ENV{PATH_INFO} = $r->notes('PP_PATH_INFO');
		$ENV{DOCUMENT_URI} = $ENV{PATH_INFO};
		$ENV{PATH_TRANSLATED} = $r->notes('PP_PATH_TRANSLATED');
	} else {
		$r->log->info($qualifiedName.' has no notes.');
	}
	if ($r->method eq 'POST'){ # it NEVER has notes...
                my $gwi = 'CGI/1.1';
                $ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		# POST features:
		# since the stdin has a broken structure when passed through the perl-UNIX-pipe
		# I emulate the appropriate GET request to the pp-binary...
		delete($ENV{CONTENT_LENGTH});
		delete($ENV{CONTENT_TYPE});
		my $content = $r->content;
		$ENV{QUERY_STRING} = $content;
		$ENV{REQUEST_METHOD} = 'GET';
	}
	unless ($fh = FileHandle->new("$filename |")) {
		$r->log->error($qualifiedName.' aborts: Fails to obtain incoming data handle for '.$r->filename);
		return NOT_FOUND;
	}
	# lucky to proceed:
	my $headers = retrieve_all_cgi_headers_via ($fh);
	$r->send_cgi_header($headers);
	if ($r->header_only){
		$fh->close;
		$r->log->info($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
		return OK;
	}

	# Create the deflation stream:
	my ($gzip_handler, $status) = deflateInit(
	     -Level      => Z_BEST_COMPRESSION(),
	     -WindowBits => - MAX_WBITS(),);
	unless ($status == Z_OK()){ # log the Error:
		my $message = 'Cannot create a deflation stream. ';
		$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
		return SERVER_ERROR;
	}
	# Create the first outgoing portion of the content:
	my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
	my $chunkBody = $gzipHeader;
	my $body = ''; # incoming content
	my $partialSourceLength = 0; # the length of the source associated with the portion gzipped in current chunk

	my $buf;
	{
	local $\;
	my $lbr = Compress::LeadingBlankSpaces->new();
	while (defined($buf = <$fh>)){
		$buf = $lbr->squeeze_string($buf) if $light_compression;
		next unless $buf;
		$body .= $buf;
		my $localPartialFlush = 0; # should be false default inside this loop
		$partialSourceLength += length($buf); # to deside if the partial flush is required
		if ($partialSourceLength > $minChunkSizeSource){
			$localPartialFlush = 1; # just true
			$partialSourceLength = 0; # for the next pass
		}
		my ($out, $status) = $gzip_handler->deflate(\$buf);
		if ($status == Z_OK){
			$chunkBody .= $out; # it may bring nothing indeed...
			$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
		} else { # log the Error:
			$fh->close;
			$gzip_handler = undef; # clean it up...
			$r->log->error($qualifiedName.' aborts: Cannot gzip this section. gzip status='.$status);
			return SERVER_ERROR;
		}
		if (length($chunkBody) > $minChunkSize ){ # send it...
			print ($chunkBody);
			$chunkBody = ''; # for the next iteration
		}
	}
	}
	$fh->close;
	$chunkBody .= $gzip_handler->flush();
	$gzip_handler = undef; # clean it up...
	# Append the checksum:
	$chunkBody .= pack("V V", crc32(\$body), length($body)) ;
	print ($chunkBody);
	$chunkBody = '';
	if ($r->notes('ref_cache_files')){
		$r->notes('ref_source' => \$body);
		$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
	}
	$r->log->info($qualifiedName.' is done OK for '.$r->filename);
	return OK;

} # unless ($can_chunk)

	# This is HTTP/1.1 or higher:
	$r->header_out('Transfer-Encoding','chunked'); # to overwrite the default Apache behavior...
	unless ($can_gzip) {
		# Send chunked content, which might be lightly compressed only, when the compression is ordered...
		# server-side cache control might be in effect, if ordered...
		#
		my $minChunkSizePP = $r->dir_config('minChunkSizePP') || MIN_CHUNK_SIZE_PP_DEFAULT;
		$r->log->info($qualifiedName.' no gzip for '.$r->the_request
			.' min_chunk_size='.$minChunkSizePP);

		if ($filter) {
			# make filter-chain item with chunks...
			$r = $r->filter_register;
			$fh = $r->filter_input();
			unless ($fh){
				my $message = ' Fails to obtain the Filter data handle for ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return SERVER_ERROR;
			}
			my $headers = retrieve_all_cgi_headers_via ($fh);
			$r->send_cgi_header($headers); # just for the case...
			if ($r->header_only){
				$r->log->info($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
				return OK;
			}
			my $body = ''; # incoming content
			if ($light_compression) {
				$body = send_lightly_compressed_stream_chunked($r, $fh, $minChunkSizePP);
			} else { # no light compression
				my $chunkBody = '';
				while (<$fh>) {
					$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
					# to create the effective compression within the later stage,
					# when the caching is ordered...
					$chunkBody .= $_;
					if (length($chunkBody) > $minChunkSizePP){ # send it...
						print (chunk_out($chunkBody));
						$chunkBody = ''; # for the next iteration
					}
				}
				if (length($chunkBody) > 0){ # send it...
					print (chunk_out($chunkBody));
					$chunkBody = '';
				}
			}
			# Append the empty chunk to finish the deal:
			print ('0'.$HttpEol.$HttpEol);

			if ($r->notes('ref_cache_files')){
				$r->notes('ref_source' => \$body);
				$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
			}
			$r->log->info($qualifiedName.' is done OK for '.$r->filename);
			return OK;
		} # if ($filter)

		unless ($binaryCGI) { # Transfer a Plain File responding to the main request

			unless (-e $r->finfo){
				$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
				return NOT_FOUND;
			}
			if ($r->method_number != M_GET){
				my $message = ' is not allowed for request targeting ';
				$r->log->error($qualifiedName.' aborts: '.$r->method.$message.$r->filename);
				return HTTP_METHOD_NOT_ALLOWED;
			}
			unless ($fh = Apache::File->new($r->filename)){
				my $message = ' file permissions deny server access to ';
				$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
				return FORBIDDEN;
			}
			# since the file is opened successfully, I need to flock() it...
			my $success = 0;
			my $tries = 0;
			while ($tries++ < MAX_ATTEMPTS_TO_TRY_FLOCK){
				last if $success = flock ($fh, LOCK_SH|LOCK_NB);
				$r->log->warn($qualifiedName.' is waiting for read flock of '.$r->filename);
				sleep (1); # wait a second...
			}
			unless ($success){
				$fh->close;
				$r->log->error($qualifiedName.' aborts: Fails to obtain flock on '.$r->filename);
				return SERVER_ERROR;
			}
			$r->send_http_header;
			if ($r->header_only){
				$r->log->info($qualifiedName.' request for header only is OK for ', $r->filename);
				return OK;
			}
			my $body = ''; # incoming content
			if ($light_compression) {
				$body = send_lightly_compressed_stream_chunked($r, $fh, $minChunkSizePP);
			} else { # no light compression
				my $chunkBody = '';
				while (<$fh>) {
					$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
					# to create the effective compression within the later stage,
					# when the caching is ordered...
					$chunkBody .= $_;
					if (length($chunkBody) > $minChunkSizePP){ # send it...
						print (chunk_out($chunkBody));
						$chunkBody = ''; # for the next iteration
					}
				}
				if (length($chunkBody) > 0){ # send it...
					print (chunk_out($chunkBody));
					$chunkBody = '';
				}
			}
			$fh->close;
			# Append the empty chunk to finish the deal:
			print ('0'.$HttpEol.$HttpEol);

			if ($r->notes('ref_cache_files')){
				$r->notes('ref_source' => \$body);
				$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
			}
			$r->log->warn($qualifiedName.' is done OK for '.$r->the_request.' targeted '.$r->filename);
			return OK;
		} # unless ($binaryCGI)

		# It is Binary CGI to transfer with no gzip compression:
		#
		# double-check the target file's existance and access permissions:
		unless (-e $r->finfo){
			$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
			return NOT_FOUND;
		}
		my $filename = $r->filename();
		unless (-f $filename and -x _ ) {
			$r->log->error($qualifiedName.' aborts: no exec permissions for '.$r->filename);
			return SERVER_ERROR;
		}
		$r->chdir_file();

		# make %ENV appropriately:
		my $gwi = 'CGI/1.1';
		$ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		if ($r->method eq 'POST'){ # it NEVER has notes...
			# POST features:
			# since the stdin has a broken structure when passed through the perl-UNIX-pipe
			# I emulate the appropriate GET request to the pp-binary...
			delete($ENV{CONTENT_LENGTH});
			delete($ENV{CONTENT_TYPE});
			my $content = $r->content;
			$ENV{QUERY_STRING} = $content;
			$ENV{REQUEST_METHOD} = 'GET';
		}
		unless ($fh = FileHandle->new("$filename |")) {
			$r->log->error($qualifiedName.' aborts: Fails to obtain incoming data handle for '.$r->filename);
			return NOT_FOUND;
		}
		# lucky to proceed:
		my $headers = retrieve_all_cgi_headers_via ($fh);
		$r->send_cgi_header($headers);
		if ($r->header_only){
			$fh->close;
			$r->log->warn($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
			return OK;
		}
		my $body = ''; # incoming content
		if ($light_compression) {
			local $\;
			$body = send_lightly_compressed_stream_chunked($r, $fh, $minChunkSizePP);
		} else { # no any compression, just chunked:
			local $\;
			my $chunkBody = '';
			while (<$fh>) {
				$body .= $_ if $r->notes('ref_cache_files'); # accumulate all here
				# to create the effective compression within the later stage,
				# when the caching is ordered...
				$chunkBody .= $_;
				if (length($chunkBody) > $minChunkSizePP){ # send it...
					print (chunk_out($chunkBody));
					$chunkBody = ''; # for the next iteration
				}
			}
			if (length($chunkBody) > 0){ # send it...
				print (chunk_out($chunkBody));
				$chunkBody = '';
			}
		}
		$fh->close;
		# Append the empty chunk to finish the deal:
		print ('0'.$HttpEol.$HttpEol);

		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->warn($qualifiedName.' is done OK for '.$r->the_request);
		return OK;
	} # unless ($can_gzip)

	# GZIP the outgoing stream...
	# ===========================
	# retrieve settings from config:
	my $minChunkSize = $r->dir_config('minChunkSize') || MIN_CHUNK_SIZE_DEFAULT;
	my $minChunkSizeSource = $r->dir_config('minChunkSizeSource') || MIN_CHUNK_SIZE_SOURCE_DEFAULT;
	$r->log->info($qualifiedName.' starts gzip using minChunkSizeSource = '.$minChunkSizeSource.
		' minChunkSize = '.$minChunkSize.' for '.$r->filename);
	$r->content_encoding('gzip');
	$r->header_out('Transfer-Encoding','chunked'); # to overwrite the default Apache behavior...
	#
	# In reference to mod_gzip interoperability with poorly written proxies, 
	# Michael Schroepl recently wrote:
	# > You do need to include a header like
	# > 
	# > Vary: User-Agent,Accept-Encoding
	# > 
	# > with all responses, compressed or not.  If you don't, then it's your 
	# > fault, not the proxy's fault, when something fails.
	#
	$r->header_out('Vary','Accept-Encoding');

	# Advanced control over the client/proxy Cache:
	#
	my $extra_vary = $r->dir_config('Vary');
	my $current_vary = $r->header_out("Vary");
	my $new_vary = join (',',$current_vary,$extra_vary);
	$r->header_out("Vary" => $new_vary) if $extra_vary;

	if ($filter) {
		$r = $r->filter_register;
		$fh = $r->filter_input();
		unless ($fh){
			my $message = ' Fails to obtain the Filter data handle for ';
			$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
			return SERVER_ERROR;
		}
		if (cgi_headers_from_script($r)) {
			my $headers = retrieve_all_cgi_headers_via ($fh);
			$r->log->debug($qualifiedName.' has CGI-header(s): '.$headers.' from '.$r->filename);
			$r->send_cgi_header($headers);
		} else { # create the own set of HTTP headers:
			$r->log->debug($qualifiedName.' creates own HTTP headers for '.$r->the_request);
			$r->content_type("text/html");
			$r->send_http_header;
		}
		if ($r->header_only){
			$r->log->info($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
			return OK;
		}
		my $body = ''; # incoming content
		# Create the deflation stream:
		my ($gzip_handler, $status) = deflateInit(
		     -Level      => Z_BEST_COMPRESSION(),
		     -WindowBits => - MAX_WBITS(),);
		unless ($status == Z_OK()){ # log the Error:
			my $message = 'Cannot create a deflation stream. ';
			$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
			return SERVER_ERROR;
		}
		# Create the first outgoing portion of the content:
		my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
		my $chunkBody = $gzipHeader;

		my $partialSourceLength = 0;	# the length of the source
						# associated with the portion gzipped in current chunk
		my $lbr = Compress::LeadingBlankSpaces->new();
		while (<$fh>) {
			$_ = $lbr->squeeze_string($_) if $light_compression;
			my $localPartialFlush = 0; # should be false default inside this loop
			$body .= $_; # accumulate all here to create the effective compression
				     # within the cleanup stage, when the caching is ordered...
			$partialSourceLength += length($_); # to deside if the partial flush is required
			if ($partialSourceLength > $minChunkSizeSource){
				$localPartialFlush = 1; # just true
				$partialSourceLength = 0; # for the next pass
			}
			my ($out, $status) = $gzip_handler->deflate(\$_);
			if ($status == Z_OK){
				$chunkBody .= $out; # it may bring nothing indeed...
				$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
			} else { # log the Error:
				$gzip_handler = undef; # clean it up...
				my $message = 'Cannot gzip the Current Section. ';
				$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
				return SERVER_ERROR;
			}
			if (length($chunkBody) > $minChunkSize ){ # send it...
				print (chunk_out($chunkBody));
				$chunkBody = ''; # for the next iteration
			}
		}
		$chunkBody .= $gzip_handler->flush();
		$gzip_handler = undef; # clean it up...
		# Append the checksum:
		$chunkBody .= pack("V V", crc32(\$body), length($body));
		print (chunk_out($chunkBody));
		$chunkBody = '';

		# Append the empty chunk to finish the deal:
		print ('0'.$HttpEol.$HttpEol);

		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->info($qualifiedName.' is done OK for '.$r->filename);
		return OK;
	} # if ($filter)

	unless ($binaryCGI) { # Transfer a Plain File gzipped, responding to the main request

		unless (-e $r->finfo){
			$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
			return NOT_FOUND;
		}
		if ($r->method_number != M_GET){
			my $message = ' is not allowed for redirected request targeting ';
			$r->log->error($qualifiedName.' aborts: '.$r->method.$message.$r->filename);
			return HTTP_METHOD_NOT_ALLOWED;
		}
		unless ($fh = Apache::File->new($r->filename)){
			my $message = ' file permissions deny server access to ';
			$r->log->error($qualifiedName.' aborts:'.$message.$r->filename);
			return FORBIDDEN;
		}
		# since the file is opened successfully, I need to flock() it...
		my $success = 0;
		my $tries = 0;
		while ($tries++ < MAX_ATTEMPTS_TO_TRY_FLOCK){
			last if $success = flock ($fh, LOCK_SH|LOCK_NB);
			$r->log->warn($qualifiedName.' is waiting for read flock of '.$r->filename);
			sleep (1); # wait a second...
		}
		unless ($success){
			$fh->close;
			$r->log->error($qualifiedName.' aborts: Fails to obtain flock on '.$r->filename);
			return SERVER_ERROR;
		}
		$r->content_type("text/html");
		$r->send_http_header;
		if ($r->header_only){
			$r->log->info($qualifiedName.' request for header only is OK for ', $r->filename);
			return OK;
		}
		# Create the deflation stream:
		my ($gzip_handler, $status) = deflateInit(
		     -Level      => Z_BEST_COMPRESSION(),
		     -WindowBits => - MAX_WBITS(),);
		unless ($status == Z_OK()){ # log the Error:
			$fh->close; # and unlock...
			my $message = 'Cannot create a deflation stream. ';
			$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
			return SERVER_ERROR;
		}
		# Create the first outgoing portion of the content:
		my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
		my $chunkBody = $gzipHeader;

		my $body = ''; # incoming content
		my $partialSourceLength = 0; # the length of the source associated with the portion gzipped in current chunk
		my $lbr = Compress::LeadingBlankSpaces->new();
		while (<$fh>) {
			$_ = $lbr->squeeze_string($_) if $light_compression;
			my $localPartialFlush = 0; # should be false default inside this loop
			$body .= $_;    # accumulate all here to create the effective compression within the cleanup stage,
					# when the caching is ordered...
			$partialSourceLength += length($_); # to deside if the partial flush is required
			if ($partialSourceLength > $minChunkSizeSource){
				$localPartialFlush = 1; # just true
				$partialSourceLength = 0; # for the next pass
			}
			my ($out, $status) = $gzip_handler->deflate(\$_);
			if ($status == Z_OK){
				$chunkBody .= $out; # it may bring nothing indeed...
				$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
			} else { # log the Error:
				$fh->close; # and unlock...
				$gzip_handler = undef; # clean it up...
				my $message = 'Cannot gzip the Current Section. ';
				$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
				return SERVER_ERROR;
			}
			if (length($chunkBody) > $minChunkSize ){ # send it...
				print (chunk_out($chunkBody));
				$chunkBody = ''; # for the next iteration
			}
		}
		$fh->close; # and unlock...
		$chunkBody .= $gzip_handler->flush();
		$gzip_handler = undef; # clean it up...
		# Append the checksum:
		$chunkBody .= pack("V V", crc32(\$body), length($body)) ;
		print (chunk_out($chunkBody));
		$chunkBody = '';
		# Append the empty chunk to finish the deal:
		print ('0'.$HttpEol.$HttpEol);
		if ($r->notes('ref_cache_files')){
			$r->notes('ref_source' => \$body);
			$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
		}
		$r->log->info($qualifiedName.' is done OK for '.$r->filename);
		return OK;
	} # unless ($binaryCGI)

	# It is Binary CGI to transfer with gzip compression:
	#
	# double-check the target file's existance and access permissions:
	unless (-e $r->finfo){
		$r->log->error($qualifiedName.' aborts: file does not exist: '.$r->filename);
		return NOT_FOUND;
	}
	my $filename = $r->filename();
	unless (-f $filename and -x _ ) {
		$r->log->error($qualifiedName.' aborts: no exec permissions for '.$r->filename);
		return SERVER_ERROR;
	}
	$r->chdir_file();

	# make %ENV appropriately:
	if ($r->notes('PP_PATH_TRANSLATED')){
		$r->log->info($qualifiedName.' has notes: PP_PATH_TRANSLATED='.$r->notes('PP_PATH_TRANSLATED'));
		my $gwi = 'CGI/1.1';
		$ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		$ENV{QUERY_STRING} = $r->notes('PP_QUERY_STRING');
		$ENV{SCRIPT_NAME} = $r->notes('PP_SCRIPT_NAME');
		$ENV{DOCUMENT_NAME}='index.html';
		$ENV{DOCUMENT_PATH_INFO}='';

		$ENV{REQUEST_URI} = $ENV{SCRIPT_NAME}.'?'.$ENV{QUERY_STRING};
		$ENV{PATH_INFO} = $r->notes('PP_PATH_INFO');
		$ENV{DOCUMENT_URI} = $ENV{PATH_INFO};
		$ENV{PATH_TRANSLATED} = $r->notes('PP_PATH_TRANSLATED');
	} else {
		$r->log->info($qualifiedName.' has no notes.');
	}
	if ($r->method eq 'POST'){ # it NEVER has notes...
                my $gwi = 'CGI/1.1';
                $ENV{GATEWAY_INTERFACE} = $gwi;
		kill_over_env();

		# POST features:
		# since the stdin has a broken structure when passed through the perl-UNIX-pipe
		# I emulate the appropriate GET request to the pp-binary...
		delete($ENV{CONTENT_LENGTH});
		delete($ENV{CONTENT_TYPE});
		my $content = $r->content;
		$ENV{QUERY_STRING} = $content;
		$ENV{REQUEST_METHOD} = 'GET';
	}
	unless ($fh = FileHandle->new("$filename |")) {
		$r->log->error($qualifiedName.' aborts: Fails to obtain incoming data handle for '.$r->filename);
		return NOT_FOUND;
	}
	# lucky to proceed:
	my $headers = retrieve_all_cgi_headers_via ($fh);
	$r->send_cgi_header($headers);
	if ($r->header_only){
		$fh->close;
		$r->log->warn($qualifiedName.' request for HTTP header only is done OK for '.$r->the_request);
		return OK;
	}

	# Create the deflation stream:
	my ($gzip_handler, $status) = deflateInit(
	     -Level      => Z_BEST_COMPRESSION(),
	     -WindowBits => - MAX_WBITS(),);
	unless ($status == Z_OK()){ # log the Error:
		my $message = 'Cannot create a deflation stream. ';
		$r->log->error($qualifiedName.' aborts: '.$message.'gzip status='.$status);
		return SERVER_ERROR;
	}
	# Create the first outgoing portion of the content:
	my $gzipHeader = pack("c" . MIN_HDR_SIZE, MAGIC1, MAGIC2, Z_DEFLATED(), 0,0,0,0,0,0, OSCODE);
	my $chunkBody = $gzipHeader;
	my $body = ''; # incoming content
	my $partialSourceLength = 0; # the length of the source associated with the portion gzipped in current chunk

	my $buf;
	{
	local $\;
	my $lbr = Compress::LeadingBlankSpaces->new();
	while (defined($buf = <$fh>)){
		$buf = $lbr->squeeze_string($buf) if $light_compression;
		next unless $buf;
		$body .= $buf;
		my $localPartialFlush = 0; # should be false default inside this loop
		$partialSourceLength += length($buf); # to deside if the partial flush is required
		if ($partialSourceLength > $minChunkSizeSource){
			$localPartialFlush = 1; # just true
			$partialSourceLength = 0; # for the next pass
		}
		my ($out, $status) = $gzip_handler->deflate(\$buf);
		if ($status == Z_OK){
			$chunkBody .= $out; # it may bring nothing indeed...
			$chunkBody .= $gzip_handler->flush(Z_PARTIAL_FLUSH) if $localPartialFlush;
		} else { # log the Error:
			$fh->close;
			$gzip_handler = undef; # clean it up...
			$r->log->error($qualifiedName.' aborts: Cannot gzip this section. gzip status='.$status);
			return SERVER_ERROR;
		}
		if (length($chunkBody) > $minChunkSize ){ # send it...
			print (chunk_out($chunkBody));
			$chunkBody = ''; # for the next iteration
		}
	}
	}
	$fh->close;
	$chunkBody .= $gzip_handler->flush();
	$gzip_handler = undef; # clean it up...
	# Append the checksum:
	$chunkBody .= pack("V V", crc32(\$body), length($body)) ;
	print (chunk_out($chunkBody));
	$chunkBody = '';
	# Append the empty chunk to finish the deal:
	print ('0'.$HttpEol.$HttpEol);
	if ($r->notes('ref_cache_files')){
		$r->notes('ref_source' => \$body);
		$r->log->info($qualifiedName.' cache copy is referenced for '.$r->filename);
	}
	$r->log->info($qualifiedName.' is done OK for '.$r->filename);
	return OK;
}

1;

__END__

=head1 NAME

Apache::Dynagzip - mod_perl extension for C<Apache-1.3.X> to compress the response with C<gzip> format.

=head1 ABSTRACT

This Apache handler provides dynamic content compression of the response data stream
for C<HTTP/1.0> and C<HTTP/1.1> requests.

Standard C<gzip> compression is optionally combined with C<extra light> compression,
which eliminates leading blank spaces and/or blank lines within the source document.
This C<extra light> compression could be applied even when the client (browser)
is not capable to decompress C<gzip> format.

This handler helps to compress the outbound
HTML content usually by 3 to 20 times, and provides a list of useful features.

This handler is particularly useful for compressing outgoing web content
which is dynamically generated on the fly (using templates, DB data, XML,
etc.), when at the time of the request it is impossible to determine the
length of the document to be transmitted. Support for Perl, Java, and C
source generators is provided.

Besides the benefits of reduced document size, this approach gains efficiency
from being able to overlap the various phases of data generation, compression,
transmission, and decompression. In fact, the browser can start to
decompress a document which has not yet been completely generated.

=head1 SYNOPSIS

There is more then one way to configure Apache to use this handler...

=head2 Compress the regular (static) HTML files

 ======================================================
 Static html file (size=149208) no light compression:
 ======================================================
 httpd.conf:

  PerlModule Apache::Dynagzip
  <Files ~ "*\.html">
      SetHandler perl-script
      PerlHandler Apache::Dynagzip
  </Files>

 error_log:

 [Fri May 31 12:36:57 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is serving the main request for GET /html/wowtmovie.html HTTP/1.1
 targeting /var/www/html/wowtmovie.html via /html/wowtmovie.html
 Light Compression is Off. Source comes from Plain File.
 The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
 [Fri May 31 12:36:57 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/html/wowtmovie.html
 [Fri May 31 12:36:57 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is done OK for /var/www/html/wowtmovie.html

 client-side log:

  C05 --> S06 GET /html/wowtmovie.html HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Referer: http://devl4.outlook.net/html/
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Fri, 31 May 2002 17:36:57 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Friday, 31-May-2002 17:41:57 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 9411 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  1314 (hex) = 4884 (dec)
  3ed (hex) = 1005 (dec)
  354 (hex) = 852 (dec)
  450 (hex) = 1104 (dec)
  5e6 (hex) = 1510 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.170 seconds, Extra Delay = 0.440 seconds
  == Restored Body was 149208 bytes ==

 ======================================================
 Static html file (size=149208) with light compression:
 ======================================================
 httpd.conf:

  PerlModule Apache::Dynagzip
  <Files ~ "*\.html">
        SetHandler perl-script
        PerlHandler Apache::Dynagzip
        PerlSetVar LightCompression On
  </Files>

 error_log:

 [Fri May 31 12:49:06 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is serving the main request for GET /html/wowtmovie.html HTTP/1.1
 targeting /var/www/html/wowtmovie.html via /html/wowtmovie.html
 Light Compression is On. Source comes from Plain File.
 The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
 [Fri May 31 12:49:07 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/html/wowtmovie.html
 [Fri May 31 12:49:08 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is done OK for /var/www/html/wowtmovie.html

 client-side log:

  C05 --> S06 GET /html/wowtmovie.html HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Referer: http://devl4.outlook.net/html/
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Fri, 31 May 2002 17:49:06 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Friday, 31-May-2002 17:54:06 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 8515 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  119f (hex) = 4511 (dec)
  3cb (hex) = 971 (dec)
  472 (hex) = 1138 (dec)
  736 (hex) = 1846 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.280 seconds, Extra Delay = 0.820 seconds
  == Restored Body was 128192 bytes ==

Default values for the C<minChunkSizeSource> and the C<minChunkSize> will be in effect in this case.
To overwrite them try for example

        <IfModule mod_perl.c>
                PerlModule Apache::Dynagzip
		<Files ~ "*\.html">
                        SetHandler perl-script
                        PerlHandler Apache::Dynagzip
			PerlSetVar minChunkSizeSource 36000
			PerlSetVar minChunkSize 9
		</Files>
	</IfModule>

=head2 Compress the output stream of the Perl scripts

 ===============================================================================
 GET dynamically generated (by perl script) html file with no light compression:
 ===============================================================================
 httpd.conf:

 PerlModule Apache::Filter
 PerlModule Apache::Dynagzip
 <Directory /var/www/perl/>
      SetHandler perl-script
      PerlHandler Apache::RegistryFilter Apache::Dynagzip
      PerlSetVar Filter On
      PerlSetVar UseCGIHeadersFromScript Off
      PerlSendHeader Off
      PerlSetupEnv On
      AllowOverride None
      Options ExecCGI FollowSymLinks
      Order allow,deny
      Allow from all
 </Directory>

 error_log:

 [Sat Jun  1 11:59:47 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is serving the main request for GET /perl/start_example.cgi HTTP/1.1
 targeting /var/www/perl/start_example.cgi via /perl/start_example.cgi
 Light Compression is Off. Source comes from Filter Chain.
 The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
 [Sat Jun  1 11:59:47 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/perl/start_example.cgi
 [Sat Jun  1 11:59:47 2002] [debug] /usr/local/share/perl/5.6.1/Apache/Dynagzip.pm(594):
 [client 12.250.100.179] Apache::Dynagzip default_content_handler creates own HTTP headers
 for GET /perl/start_example.cgi HTTP/1.1
 [Sat Jun  1 11:59:47 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is done OK for /var/www/perl/start_example.cgi

 client-side log:

  C05 --> S06 GET /perl/start_example.cgi HTTP/1.1
  C05 --> S06 Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/msword, */*
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Sat, 01 Jun 2002 16:59:47 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Saturday, 01-June-2002 17:04:47 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 758 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  2db (hex) = 731 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.220 seconds, Extra Delay = 0.050 seconds
  == Restored Body was 1434 bytes ==

 ============================================================================
 GET dynamically generated (by perl script) html file with light compression:
 ============================================================================
 httpd.conf:

  PerlModule Apache::Filter
  PerlModule Apache::Dynagzip
 <Directory /var/www/perl/>
        SetHandler perl-script
	PerlHandler Apache::RegistryFilter Apache::Dynagzip
	PerlSetVar Filter On
	PerlSetVar UseCGIHeadersFromScript Off
	PerlSetVar LightCompression On
	PerlSendHeader Off
	PerlSetupEnv On
	AllowOverride None
	Options ExecCGI FollowSymLinks
	Order allow,deny
        Allow from all
 </Directory>

 error_log:

 [Sat Jun  1 12:09:14 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is serving the main request for GET /perl/start_example.cgi HTTP/1.1
 targeting /var/www/perl/start_example.cgi via /perl/start_example.cgi
 Light Compression is On. Source comes from Filter Chain.
 The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
 [Sat Jun  1 12:09:14 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/perl/start_example.cgi
 [Sat Jun  1 12:09:14 2002] [debug] /usr/local/share/perl/5.6.1/Apache/Dynagzip.pm(594):
 [client 12.250.100.179] Apache::Dynagzip default_content_handler creates own HTTP headers
 for GET /perl/start_example.cgi HTTP/1.1
 [Sat Jun  1 12:09:14 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is done OK for /var/www/perl/start_example.cgi

 client-side log:

  C05 --> S06 GET /perl/start_example.cgi HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Sat, 01 Jun 2002 17:09:13 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Saturday, 01-June-2002 17:14:14 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 750 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  2d3 (hex) = 723 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.280 seconds, Extra Delay = 0.000 seconds
  == Restored Body was 1416 bytes ==

=head2 Compress the outgoing stream from the CGI binary

 ====================================================================================
 GET dynamically generated (by C-written binary) html file with no light compression:
 ====================================================================================
 httpd.conf:

 PerlModule Apache::Dynagzip
 <Directory /var/www/cgi-bin/>
     SetHandler perl-script
     PerlHandler Apache::Dynagzip
     AllowOverride None
     Options +ExecCGI
     PerlSetupEnv On
     PerlSetVar BinaryCGI On
     Order allow,deny
     Allow from all
 </Directory>

 error_log:

 [Fri May 31 18:18:17 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is serving the main request for GET /cgi-bin/mylook.cgi HTTP/1.1
 targeting /var/www/cgi-bin/mylook.cgi via /cgi-bin/mylook.cgi
 Light Compression is Off. Source comes from Binary CGI.
 The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
 [Fri May 31 18:18:17 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/cgi-bin/mylook.cgi
 [Fri May 31 18:18:17 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler has no notes.
 [Fri May 31 18:18:17 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
 is done OK for /var/www/cgi-bin/mylook.cgi

 client-side log:

  C05 --> S06 GET /cgi-bin/mylook.cgi HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Fri, 31 May 2002 23:18:17 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Friday, 31-May-2002 23:23:17 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 1002 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  3cf (hex) = 975 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.110 seconds, Extra Delay = 0.110 seconds
  == Restored Body was 1954 bytes ==

 =================================================================================
 GET dynamically generated (by C-written binary) html file with light compression:
 =================================================================================
  httpd.conf:

   PerlModule Apache::Dynagzip
   <Directory /var/www/cgi-bin/>
       SetHandler perl-script
       PerlHandler Apache::Dynagzip
       AllowOverride None
       Options +ExecCGI
       PerlSetupEnv On
       PerlSetVar BinaryCGI On
       PerlSetVar LightCompression On
       Order allow,deny
       Allow from all
   </Directory>

  error_log:

  [Fri May 31 18:37:45 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
  is serving the main request for GET /cgi-bin/mylook.cgi HTTP/1.1
  targeting /var/www/cgi-bin/mylook.cgi via /cgi-bin/mylook.cgi
  Light Compression is On. Source comes from Binary CGI.
  The client Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) accepts GZIP.
  [Fri May 31 18:37:45 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
  starts gzip using minChunkSizeSource = 32768 minChunkSize = 8 for /var/www/cgi-bin/mylook.cgi
  [Fri May 31 18:37:45 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler has no notes.
  [Fri May 31 18:37:45 2002] [info] [client 12.250.100.179] Apache::Dynagzip default_content_handler
  is done OK for /var/www/cgi-bin/mylook.cgi

 client-side log:

  C05 --> S06 GET /cgi-bin/mylook.cgi HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==

  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Fri, 31 May 2002 23:37:45 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Expires: Friday, 31-May-2002 23:42:45 GMT
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 994 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  3c7 (hex) = 967 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.170 seconds, Extra Delay = 0.110 seconds
  == Restored Body was 1862 bytes ==

=head2 Dynamic Setup/Configuration from the Perl Code

Alternatively, you can control this handler from your own perl-written handler
which is serving the earlier phase of the request processing.
For example, I'm using the dynamic installation of the C<Apache::Dynagzip>
from my C<PerlTransHandler> to serve the HTML content cache appropriately.

  use Apache::RegistryFilter;
  use Apache::Dynagzip;

  . . .

  $r->handler("perl-script");
  $r->push_handlers(PerlHandler => \&Apache::RegistryFilter::handler);
  $r->push_handlers(PerlHandler => \&Apache::Dynagzip::handler);

In your perl code you can even extend the main C<config> settings (for the current request) with:

  $r->dir_config->set(minChunkSizeSource => 36000);
  $r->dir_config->set(minChunkSize => 6);

for example...

=head2 Common Notes

Over C<HTTP/1.0> handler indicates the end of data stream by closing connection.
Over C<HTTP/1.1> the outgoing data is compressed within a chunked outgoing stream,
keeping the connection alive.

The appropriate combination of the HTTP headers

	X-Module-Sender: Apache::Dynagzip
	Transfer-Encoding: chunked
	Content-Encoding: gzip
	Vary: Accept-Encoding

will be added to response when required.
No HTTP header of the C<Content-Length> will be provided in any case...

=head1 INTRODUCTION

From a historical point of view this package was developed mainly to compress the output
of a proprietary CGI binary written in C that was
widely used by Outlook Technologies, Inc. to deliver uncompressed dynamically generated
HTML content over the Internet using C<HTTP/1.0> since the mid-'90s.
We were then presented with the challenge of using the content compression
features over C<HTTP/1.1> on busy production servers, especially those serving heavy traffic on virtual hosts
of popular American broadcasting companies.

The very first our attempts to implement the static gzip approach to compress the
dynamic content helped us to scale effectively the bandwidth of BBC backend
by the cost of significantly increased latency of the content delivery.

Actually, in accordance with my own observations,
the delay of the content's download (up to the moment when the page
is able to run the onLoad() JavaScript) was not increased even on fast connections,
and it was significantly decreased on dial-ups. Indeed, the BBC
editors were not too happy to wait up to a minute sitting in front of the
sleeping screen when the backend updates some hundreds of Kbytes of the local content...

That was why I came up with the idea to use the chunked data transmission of
the gzipped content sharing some real time between the server side data
creation/compression, some data transmission, and the client side data
decompression/presentation, and providing the end users with the partially
displayed content as soon as it's possible in particular conditions of the
user's connection.

At the time we decided to go for the dynamic compression there was no
appropriate software on the market, which could be customized to target our
goals effectively. Even later in
February 2002 Nicholas Oxhøj wrote to the mod_perl mailing list about his
experience to find the Apache gzipper for the streaming outgoing content:

=over 4

=item 

I<"... I have been experimenting with all the different Apache compression modules
I have been able to find, but have not been able to get the desired result.
I have tried Apache::GzipChain, Apache::Compress, mod_gzip and mod_deflate, with
different results.  One I cannot get to work at all. Most work, but seem to collect
all the output before compressing it and sending it to the browser...>

I<... Wouldn't it be nice to have some option to specify that the handler should flush
and send the currently compressed output every time it had received a certain amount
of input or every time it had generated a certain amount of output?..>

I<... So I am basically looking for anyone who has had any success in achieving this
kind of "streaming" compression, who could direct me at an appropriate Apache module.">

=back

Unfortunately for him, the C<Apache::Dynagzip> has not yet been publicly available at that time...

Since relesed this handler is the most useful when you need to compress the outgoing
Web content, which is dynamically generated on the fly (using the templates,
DB data, XML, etc.), and when at the moment of the request it is impossible
to determine the length of the document you have to transmit.

You may benefit additionally from the fact that the handler begins the transmission
of the compressed data when the very first portion of outgoing data is arrived from
the main data source only, at the moment when probably the source big HTML document
has not been generated in full yet. So far, the transmission will be done partly at the
same time of the document creation. From other side, the internal buffer within the
handler prevents the Apache from the creation of too short chunks (for C<HTTP/1.1>).

In order to simplify the use of this handler on public/open_source sites,
the content compression over HTTP/1.0 was added to this handler since the version 0.06.
This implementation helps to avoid the dynamic invocation of the Apache handler
for the content generation phase, providing wider service from one the same statically configured handler.

=head2 Acknowledgments

Thanks to Tom Evans, Valerio Paolini, and Serge Bizyayev for their valuable idea contributions and multiple testing.
Thanks to Igor Sysoev and Henrik Nordstrom who helped me to understand better the HTTP/1.0 compression features.

Obviously, I hold the full responsibility for how all those contributions are used here.

=head1 DESCRIPTION

The main pupose of this package is to serve the C<content generation phase> within the mod_perl enabled
C<Apache 1.3.X>, providing the dynamic on the fly compression of web content.
It is done with the use of C<zlib> library via the C<Compress::Zlib> perl interface
to serve both C<HTTP/1.0> and C<HTTP/1.1> requests from those clients/browsers,
who understands C<gzip> format and can decompress this type of data on the fly.

This handler does never C<gzip> content for those clients/browsers,
who fails to declare the ability to decompress C<gzip> format.
In fact, this handler mainly serves as a kind of
customizable filter of outbound web content for C<Apache 1.3.X>.

This handler is supposed to be used in the C<Apache::Filter> chain mostly to serve the
outgoing content dynamically generated on the fly by Perl and/or Java.
It is featured to serve the regular CGI binaries (C-written for examle)
as a standalong handler out of the C<Apache::Filter> chain.
As an extra option, this handler can be used to compress dynamically the huge static
files, and to transfer the gzipped content in the form of stream back to the
client browser. For the last purpose the C<Apache::Dynagzip> handler should be used as
a standalong handler out of the C<Apache::Filter> chain too.

Working over the C<HTTP/1.0> this handler indicates the end of data stream by closing connection.
Indeed, over C<HTTP/1.1> the outgoing data is compressed within a chunked outgoing stream,
keeping the connection alive. Resonable control over the chunk-size is provided in this case.

In order to serve better the older web clients
the C<extra light> compression is provided independently to remove
unnecessary leading blank spaces and/or blank lines
from the outgoing web content. This C<extra light> compression could be combined with
the main C<gzip> compression, when necessary.

The list of features of this handler includes:

=over 4

=item ·
Support for both HTTP/1.0 and HTTP/1.1 requests.

=item ·
Reasonable control over the size of content chunks for HTTP/1.1.

=item ·
Support for Perl, Java, or C/C++ CGI applications in order to provide dynamic on-the-fly compression of outbound content.

=item ·
Optional C<extra light> compression for all browsers, including older ones that incapable to decompress gzipped content.

=item ·
Optional control over the duration of the content's life in client/proxy local cache.

=item ·
Limited control over the proxy caching.

=item ·
Optional support for server-side caching of dynamically generated content.

=back

=head2 Compression Features

C<Apache::Dynagzip> provides content compression for both C<HTTP/1.0> and C<HTTP/1.1> when appropriate.

There are two types of compression, which could be applied to the outgoing content by this handler:

  - extra light compression
  - gzip compression

in any appropriate combination.

An C<extra light> compression is provided to remove leading blank spaces and/or blank lines
from the outgoing web content. It is supposed to serve the ASCII data types like C<html>,
C<JavaScript>, C<css>, etc. The implementation of C<extra light> compression is turned off
by default. It could be turned on with the statement

  PerlSetVar LightCompression On

in your C<httpd.conf>. Any other value turns the C<extra light> compression off.

The main C<gzip> format is described in rfc1952.
This type of compression is applied when the client is recognized as capable
to decompress C<gzip> format on the fly. In this version the decision is under the control
of whether the client sends the C<Accept-Encoding: gzip> HTTP header, or not.

On C<HTTP/1.1>, when the C<gzip> compression is in effect, handler keeps the resonable control
over the size of the chunks and over the compression ratio
using the combination of two internal variables which could be set in your C<httpd.conf>:

  minChunkSizeSource
  minChunkSize

The C<minChunkSizeSource> defines the minimum length of the source stream which C<zlib> may
accumulate in its internal buffer.

=over 4

=item Note:

The compression ratio depends on the length of the data,
accumulated in that buffer;
More data we keep over there - better ratio will be achieved...

=back

When the length defined by the C<minChunkSizeSource> is exceeded, the handler flushes the
internal buffer of C<zlib> and transfers the accumulated portion of the compreesed data
to the own internal buffer in order to create appropriate chunk(s).

This buffer is not nessessarily be fransfered to Appache immediately. The decision is
under the control of the C<minChunkSize> internal variable. When the size of the buffer
exceeds the value of C<minChunkSize> the handler chunks the internal buffer
and transfers the accumulated data to the Client.

This approach helps to create the effective compression combined with the limited latency.

For example, when I use

  PerlSetVar minChunkSizeSource 16000
  PerlSetVar minChunkSize 8

in my C<httpd.conf> to compress the dynamically generated content of the size of some
54,000 bytes, the client side log

  C05 --> S06 GET /pipe/pp-pipe.pl/big.html?try=chunkOneMoreTime HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==
  
  ## Sockets 6 of 4,5,6 need checking ##
  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Thu, 21 Feb 2002 20:01:47 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Vary: Accept-Encoding
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 6034 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  949 (hex) = 2377 (dec)
  5e6 (hex) = 1510 (dec)
  5c5 (hex) = 1477 (dec)
  26e (hex) = 622 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.990 seconds, Extra Delay = 0.110 seconds
  == Restored Body was 54655 bytes ==

shows that the first chunk consists of the gzip header only (10 bytes).
This chunk was sent as soon as the handler received the first portion of the data
generated by the foreign CGI script. The data itself at that moment has been
storied in the zlib's internal buffer, because the C<minChunkSizeSource> is big enough.

=over 4

=item Note:

Longer we allow zlib to keep its internal buffer - better compression ratio it makes for us...

=back

So far, in this example we have obtained the compression ratio at about 9 times.

In this version the handler provides defaults:

  minChunkSizeSource = 32768
  minChunkSize = 8

for your convenience.

In case of C<gzip> compressed response to C<HTTP/1.0> request, handler uses C<minChunkSize>
and C<minChunkSizeSource> values to
limit the minimum size of internal buffers in order
to provide appropriate compression ratio, and to avoid multiple short outputs to the core Apache.

=head2 Chunking Features

On C<HTTP/1.1> this handler overwrites the default Apache behavior, and keeps the own control over the
chunk-size when it is possible. In fact, handler provides the soft control over the chunk-size only:
It does never cut the incoming string in order to create a chunk of a particular size.
Instead, it controls the minimum size of the chunk only.
I consider this approach reasonable, because to date the HTTP chunk-size is not coordinated with the
packet-size on transport level.

In case of gzipped output the minimum size of the chunk is under the control of internal variable

  minChunkSize

In case of uncompressed output, or the C<extra light> compression only,
the minimum size of the chunk is under the control of internal variable

  minChunkSizePP

In this version for your convenience the handler provides defaults:

  minChunkSize = 8
  minChunkSizePP = 8192

You may overwrite the default values of these variables in your C<httpd.conf> if necessary.

=over 4

=item Note:

The internal variable C<minChunkSize> should be treated carefully
together with the C<minChunkSizeSource> (see Compression Features).

=back

In this version handler does not keep the control over the chunk-size when it serves the internally redirected request.
An appropriate warning is placed to C<error.log> in this case.

In case of C<gzip> compressed response to C<HTTP/1.0> request, handler uses C<minChunkSize>
and C<minChunkSizeSource> values to
limit the minimum size of internal buffers in order
to provide appropriate compression ratio, and to avoid multiple short outputs to the core Apache.

=head2 Filter Chain Features

As a member of the C<Apache::Filter> chain, the C<Apache::Dynagzip> handler is
supposed to be the last filter in the chain, because of the features of it's
functions: It produces the full set of required HTTP headers followed by the gzipped
content within the chunked stream.

No one of other handlers in C<Filter> chain is allowed to issue

 $r->send_http_header();

or

 $r->send_cgi_header();

The only acceptable HTTP information from the old CGI applications is the C<Content-Type> CGI header
which should be the first line followed by the empty line.
This line is optional in accordance with the C<CGI/1.0> description, and many
known old scripts ignore this option, which should default to C<Content-Type: text/html>.
C<CGI/1.1> (see: http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html ) makes the life
even more complicated for the system administrators.

This handler is partially CGI/1.1 compatible, except the internal redirect option, which is not guaranteed.

=head2 POST Request Features

I have to serve the POST request option for the rgular CGI binary only, because in this case the handler
is standing along to serve the data flow in both directions at the moment when the C<stdin> is tied into
Apache, and could not be exposed to CGI binary transparently.

To solve the problem I alter POST with GET internally doing the required incoming data transformations.
It could cause a problem, when you have a huge incoming stream from your client (more than 4K bytes).

=head2 Control over the Client Cache

The control over the lifetime of the response in client's cache is provided with C<Expires> HTTP header (see rfc2068):

The Expires entity-header field gives the date/time after which the response should be considered stale.
A stale cache entry may not normally be returned by a cache (either a proxy cache or an user agent cache)
unless it is first validated with the origin server (or with an intermediate cache that has a fresh copy
of the entity). The format is an absolute date and time as defined by HTTP-date in section 3.3;
it MUST be in rfc1123-date format: C<Expires = "Expires" ":" HTTP-date>

This handler creates the C<Expires> HTTP header, adding the C<pageLifeTime> to the date-time
of the request. The internal variable C<pageLifeTime> has default value

  pageLifeTime = 300 # sec.

which could be overwriten in C<httpd.conf> for example as:

  PerlSetVar pageLifeTime 1800

to make the C<pageLifeTime = 30 minutes>.

Within the lifetime the client (browser) will
not even try to access the server when you reach the same URL again.
Instead, it restarts the page from the local cache.

It's important to point out here, that all initial JavaScripts will be restarted indeed,
so you can rotate your advertisements and dynamic content when needed.

The second important point should be mentioned here: when you click the "Refresh" button, the
browser will reload the page from the server unconditionally. This is right behavior,
because it is exactly what the end-user expects from the "Refresh" button.

=over 4

=item Note:

the lifetime defined by Expires depends on accuracy of time settings on client
side. If your client's local clock is running 1 hour back, the cached copy of
the page will be alive 60 minutes longer on that machine.

=back

=head2 Support for the Server-Side Cache

To support the Server-Side Cache I place the reference to the dynamically generated document to the C<notes()>
when the Server-Side Cache Support is ordered. The referenced document could be already compressed with
C<extra light> compression, if it was ordered for the current request.

The effective C<gzip> compression is supposed to take place within the C<log> stage of the request processing.

From the historical point of view, the development of this handler was a stage of a wider project,
named C<Apache::ContentCache>, which is supposed to provide the content caching capabilities
to the wide range of arbitrary sites, being generated on the fly for some reasons.
In that project the C<Apache::Dynagzip> handler is used in the dynamically generated chain of Apache handlers
for various phases of the request processing to filter the content generation phase of the appropriate request.
To be compatible with the C<Apache::ContentCache> flow chart, the C<Apache::Dynagzip> handler
recognizes the optional reference in the C<notes()>, named C<ref_cache_files>.
When the C<ref_cache_files> is defined within the C<notes()> table,
the C<Apache::Dynagzip> handler creates one more reference named C<ref_source>
within the C<notes()> to reference the full body of uncompressed incoming document
for the post request processing phase.

You usually should not care about this feature of the C<Apache::Dynagzip> handler
unless you use it in your own chain of handlers for the various phases of the request processing.

=head2 Control over the Proxy Cache.

Control over the possible proxy cache is provided with C<Vary>
HTTP header (see rfc2068 for details).
In this version the header is always generated in form of

=over 4

=item C<Vary: Accept-Encoding>

=back

for gzipped output only.

Advanced control over the proxy cache is provided since the version 0.07
with optional extension of Vary HTTP header.
This extension could be placed into your configuration file, using directive

=over 4

=item C<PerlSetVar Vary E<lt>valueE<gt>>

=back

Particularly, it might be helpful to indicate the content, which depends on some conditions,
other than just compression features.
For example, when the content is personalized, someone might wish to use
the * C<Vary> extension to prevent any proxy caching.

When the outgoing content is gzipped, this extension will be appended to the regular C<Vary> header,
like in the following example:

Using the following fragment within the C<http.conf>:

  PerlModule Apache::Dynagzip
  <Files ~ "*\.html">
    SetHandler perl-script
    PerlHandler Apache::Dynagzip
    PerlSetVar LightCompression On
    PerlSetVar Vary *
  </Files>

We observe the client-side log in form of:

  C05 --> S06 GET /devdoc/Dynagzip/Dynagzip.html HTTP/1.1
  C05 --> S06 Accept: */*
  C05 --> S06 Referer: http://devl4.outlook.net/devdoc/Dynagzip/
  C05 --> S06 Accept-Language: en-us
  C05 --> S06 Accept-Encoding: gzip, deflate
  C05 --> S06 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)
  C05 --> S06 Host: devl4.outlook.net
  C05 --> S06 Pragma: no-cache
  C05 --> S06 Accept-Charset: ISO-8859-1
  == Body was 0 bytes ==
  
  C05 <-- S06 HTTP/1.1 200 OK
  C05 <-- S06 Date: Sun, 11 Aug 2002 21:28:43 GMT
  C05 <-- S06 Server: Apache/1.3.22 (Unix) Debian GNU/Linux mod_perl/1.26
  C05 <-- S06 X-Module-Sender: Apache::Dynagzip
  C05 <-- S06 Expires: Sunday, 11-August-2002 21:33:43 GMT
  C05 <-- S06 Vary: Accept-Encoding,*
  C05 <-- S06 Transfer-Encoding: chunked
  C05 <-- S06 Content-Type: text/html; charset=iso-8859-1
  C05 <-- S06 Content-Encoding: gzip
  C05 <-- S06 == Incoming Body was 11311 bytes ==
  == Transmission: text gzip chunked ==
  == Chunk Log ==
  a (hex) = 10 (dec)
  1c78 (hex) = 7288 (dec)
  f94 (hex) = 3988 (dec)
  0 (hex) = 0 (dec)
  == Latency = 0.160 seconds, Extra Delay = 0.170 seconds
  == Restored Body was 47510 bytes ==

=head1 CUSTOMIZATION

Do your best to avoid the implementation of this handler in internally redirected requests.
It does not help much in this case. Read your C<error.log> carefully to find the appropriate
warnings. Tune your C<http.conf> carefully to take the most from opportunities offered
by this handler.

To select the type of the content's source follow the rules:

=over 4

=item 

- use C<Apache::Filter> chain to serve any Perl, or Java generated content. When your source
is a very old CGI-application, which fails to provide the Content-Type CGI header, use

    PerlSetVar UseCGIHeadersFromScript Off

in your httpd.conf to overwrite the Document Content-Type to default text/html.

you may use C<Apache::Filter> chain to serve another sources, when you know what you are doing.
You might wish to write your own handler and include it into C<Apache::Filter> chain,
emulating the CGI outgoing stream.
 
- use the directive

    PerlSetVar BinaryCGI On

to indicate that the source-generator is supposed to be a CGI binary. Don't use C<Apache::Filter>
chain in this case. Support for CGI/1.1 headers is always On for this type of the source.

- it will be assumed the plain file transfer, when you use the standing-along handler with
no BinaryCGI directive. The Document Content-Type is determined by Apache in this case.

=back

To control the compression ratio and the minimum size of the chunk/buffer for gzipped content
you can optionally use directives

    PerlSetVar minChunkSizeSource <value>
    PerlSetVar minChunkSize <value>

for example you can try

    PerlSetVar minChunkSizeSource 32768
    PerlSetVar minChunkSize 8

which are the default in this version. Indeed, you can use your own values, when you know what you are doing...

=over 4

=item Note:

You can improve the compression ratio when you increase the value of C<minChunkSizeSource>.
You can control the _minimum_ size of the chunk with the C<minChunkSize>.

Try to play with these values to find out your best combination!

=back

To control the minimum size of the chunk for uncompressed content over HTTP/1.1 you can optionally use the directive

    PerlSetVar minChunkSizePP <value>

To control the C<extra light> compression you can optionally use the directive

    PerlSetVar LightCompression <On/Off>

To turn On the C<extra light> compression use the directive

    PerlSetVar LightCompression On

Any other value turns the C<extra light> compression Off (default).

To control the C<pageLifeTime> in client's local cache you can optionally use the directive

    PerlSetVar pageLifeTime <value>

where the value stands for the life-length in seconds.

    PerlSetVar pageLifeTime 300

is default in this version.

=head1 TROUBLESHOOTING

This handler fails to keep the control over the chunk-size when it serves the internally redirected request.
The same time it fails to provide the C<gzip> compression.
A corresponding warning is placed to C<error.log> in this case.
Make the appropriate configuration tunings to avoid the implementation of this handler for internally redirected request(s).

The handler logs C<error>, C<warn>, C<info>, and C<debug> messages to the Apache C<error.log> file.
Please, read it first in case of any trouble.

=head1 DEPENDENCIES

This module requires these other modules and libraries:

   Apache::Constants;
   Apache::File;
   Apache::Filter 1.019;
   Apache::Log;
   Apache::URI;
   Apache::Util;
   Fcntl;
   FileHandle;

   Compress::LeadingBlankSpaces;
   Compress::Zlib 1.16;
       
  Note: the Compress::Zlib 1.16 requires the Info-zip zlib 1.0.2 or better
        (it is NOT compatible with versions of zlib <= 1.0.1).
        The zlib compression library is available at http://www.gzip.org/zlib/
    
        I didn't test this handler with previous versions of the Apache::Filter.
        Please, let me know if you have a chance to do that...

=head1 AUTHOR

Slava Bizyayev E<lt>slava@cpan.orgE<gt> - Freelance Software Developer & Consultant.

=head1 COPYRIGHT AND LICENSE

I<Copyright (C) 2002 Slava Bizyayev. All rights reserved.>

This package is free software.
You can use it, redistribute it, and/or modify it under the same terms as Perl itself.

The latest version of this module can be found on CPAN.

=head1 SEE ALSO

C<mod_perl> at F<http://perl.apache.org>

C<Compress::LeadingBlankSpaces> module can be found on CPAN.

C<Compress::Zlib> module can be found on CPAN.

The primary site for the C<zlib> compression library is F<http://www.info-zip.org/pub/infozip/zlib/>.

C<Apache::Filter> module can be found on CPAN.

F<http://www.ietf.org/rfc.html> - rfc search by number (+ index list)

F<http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html> CGI/1.1 rfc

F<http://perl.apache.org/docs/general/correct_headers/correct_headers.html> "Issuing Correct HTTP Headers" by Andreas Koenig

=cut
