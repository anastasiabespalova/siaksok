# task21
# register 
python password_coder.py --regime register --password_global your_global_pswd --pub_rsa PUBLIC_RSA_FILENAME.txt --prv_rsa PRIVARE_RSA_FILENAME.txt --pub_rabin PUBLIC_RABIN_FILENAME.txt --prv_rabin PRIVATE_RABIN_FILENAME.txt

# encode
	# no password file
python password_coder.py --regime encode --pub_rsa PUBLIC_RSA_FILENAME.txt --pub_rabin PUBLIC_RABIN_FILENAME.txt --password_local YOUR_PASSWORD
	# with password file
python password_coder.py --regime encode --pub_rsa PUBLIC_RSA_FILENAME.txt --pub_rabin PUBLIC_RABIN_FILENAME.txt --password_local YOUR_PASSWORD --pswd_file YOUR_PASSWORDS.txt 

# decode
	# no password file
python password_coder.py --regime decode --prv_rsa PRIVATE_RSA_FILENAME.txt --prv_rabin PRIVATE_RABIN_FILENAME.txt --password_global your_global_pswd --password_local YOUR_CYPHERED_PASS
	# with password file
python password_coder.py --regime decode --prv_rsa PRIVATE_RSA_FILENAME.txt --prv_rabin PRIVATE_RABIN_FILENAME.txt --password_global your_global_pswd --pswd_file YOUR_PASSWORDS.txt --pswd_num 1

# change gloabal passowrd
	# when file with passwords exists
python password_coder.py --regime change_pswd --password_global your_global_pswd --password_global_new your_global --pub_rsa PUBLIC_RSA_FILENAME.txt --prv_rsa PRIVARE_RSA_FILENAME.txt --pub_rabin PUBLIC_RABIN_FILENAME.txt --prv_rabin PRIVATE_RABIN_FILENAME.txt --pswd_file YOUR_PASSWORDS.txt
	# when no file with passwords
python password_coder.py --regime change_pswd --password_global your_global --password_global_new your_global_pswd --pub_rsa PUBLIC_RSA_FILENAME.txt --prv_rsa PRIVARE_RSA_FILENAME.txt --pub_rabin PUBLIC_RABIN_FILENAME.txt --prv_rabin PRIVATE_RABIN_FILENAME.txt

