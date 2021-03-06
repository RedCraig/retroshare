#pragma once

#include <string>

// This class handles login, meaning that it retrieves the SSL password from either
// the keyring or help.dta file, if autologin is enabled, or from the ssl_passphrase.pgp
// file, asking for the GPG password to decrypt it.
//
// This class should handle the following scenario:
//
// Normal login:
// 	- SSL key is stored  ->  do autologin
// 	- SSL key is not stored
// 			- if we're actually in the login process, ask for the gpg passwd, and decrypt the key file
// 			- if we're just trying for autologin, don't ask for the gpg passwd and return null
//
// Key creation:
// 	- the key should be stored in the gpg file.
//
class RsLoginHandler
{
	public:
		// Gets the SSL passwd by any means: try autologin, and look into gpg file if enable_gpg_key_callback==true
		//
		static bool getSSLPassword(const std::string& ssl_id,bool enable_gpg_key_callback,std::string& ssl_password) ;

		// Checks whether the ssl passwd is already in the gpg file. If the file's not here, the passwd is stored there, 
		// encrypted with the current GPG key.
		//
		static bool checkAndStoreSSLPasswdIntoGPGFile(const std::string& ssl_id,const std::string& ssl_passwd) ;

		// Stores the given ssl_id/passwd pair into the keyring, or by default into a file in /[ssl_id]/keys/help.dta
		//
		static bool enableAutoLogin(const std::string& ssl_id,const std::string& passwd) ;

		// Clears autologin entry. 
		//
		static bool clearAutoLogin(const std::string& ssl_id) ;

	private:
		static bool tryAutoLogin(const std::string& ssl_id,std::string& ssl_passwd) ;
		static bool getSSLPasswdFromGPGFile(const std::string& ssl_id,std::string& sslPassword) ;

		static std::string getSSLPasswdFileName(const std::string& ssl_id) ;
		static std::string getAutologinFileName(const std::string& ssl_id) ;
};

