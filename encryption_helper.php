<?php
/*
 * -----------------------------------------------------------------------------
 * Copyright (c) 2011, Paul Yasi
 * All rights reserved.
 * 	
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 * ----------------------------------------------------------------------------
 */


/*
 * ----------------------------------------------------------------------------
 * encrypt_command
 *
 * sends data to encrypt to stdin, returns result code
 *
 * expects a gpg command like
 * /usr/bin/gpg --homedir /home/www-data/.gnupg --armor --batch -e -r 'USERNAME'
 *
 * -----------------------------------------------------------------------------
 */
function encrypt_command ($gpg_command, $data)
{
	$descriptors = array(
			0 => array("pipe", "r"), //stdin
			1 => array("pipe", "w"), //stdout
			2 => array("pipe", "w"), //stderr
			);

	$process = proc_open($gpg_command, $descriptors, $pipes);

	if (is_resource($process)) {
		// send data to encrypt to stdin
		fwrite($pipes[0], $data);
		fclose($pipes[0]);

		// read stdout
		$stdout = stream_get_contents($pipes[1]);
		fclose($pipes[1]);

		// read stderr
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[2]);

		// It is important that you close any pipes before calling
		// proc_close in order to avoid a deadlock
		$return_code = proc_close($process);

		$return_value = trim($stdout, "\n");
		//echo "$stdout";

		if (strlen($return_value) < 1) {
			$return_value = "error: $stderr";
		}

	}

	return $return_value;

}


/*
 * ----------------------------------------------------------------------------- 
 * decrypt_command
 *
 * sends passphrase to stdin, returns decrypted data
 *
 * expects a gpg command like:
 * /usr/bin/gpg --homedir /home/www-data/.gnupg --passphrase-fd 0 --yes 
 * --no-tty --skip-verify --decrypt file.gpg
 *
 * -----------------------------------------------------------------------------
 */
function decrypt_command ($gpg_command, $passphrase)
{

	$descriptors = array(
			0 => array("pipe", "r"), //stdin
			1 => array("pipe", "w"), //stdout
			2 => array("pipe", "w"), //stderr
			);

	$process = proc_open($gpg_command, $descriptors, $pipes);

	if (is_resource($process)) {
		// send passphrase to stdin
		fwrite($pipes[0], $passphrase);
		fclose($pipes[0]);

		// read stdout
		$stdout = stream_get_contents($pipes[1]);
		fclose($pipes[1]);

		// read stderr
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[2]);

		// It is important that you close any pipes before calling
		// proc_close in order to avoid a deadlock
		$return_code = proc_close($process);

		$return_value = trim($stdout, "\n");
		//echo "$stdout";

		if (strlen($return_value) < 1) {
			$return_value = "error: $stderr";
		}

	}

	return $return_value;
}


/*
 * -----------------------------------------------------------------------------
 * sign_command
 *
 * sends passphrase to stdin for a file signature, returns nothing on success
 *
 * expects a gpg command like:
 * /usr/bin/gpg --homedir /home/www-data/.gnupg --passphrase-fd 0 --yes 
 * --no-tty --clearsign file.tmp
 *
 * ----------------------------------------------------------------------------
 */
function sign_command ($gpg_command, $passphrase)
{

	$descriptors = array(
			0 => array("pipe", "r"), //stdin
			1 => array("pipe", "w"), //stdout
			2 => array("pipe", "w"), //stderr
			);

	$process = proc_open($gpg_command, $descriptors, $pipes);

	if (is_resource($process)) {
		// send passphrase to stdin
		fwrite($pipes[0], $passphrase);
		fclose($pipes[0]);

		// read stdout
		$stdout = stream_get_contents($pipes[1]);
		fclose($pipes[1]);

		// read stderr
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[2]);       

		// It is important that you close any pipes before calling
		// proc_close in order to avoid a deadlock
		$return_code = proc_close($process);

		$return_value = trim($stdout, "\n");
		//echo "$stdout";

		if (strlen($stderr) > 0) {
			$return_value = "error: $stderr";
		}

	}

	return $return_value;
}
?>
