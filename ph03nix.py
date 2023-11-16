#!/usr/bin/env python2
# -*- coding: utf-8 -*-


from __future__ import division
from __future__ import print_function
import argparse
from argparse import RawTextHelpFormatter
import base64
from colorama import Fore, Back, Style
import warnings
warnings.filterwarnings("ignore")
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import glob
import hashlib
import math
from natsort import natsorted
import os
import random
import stdiomask
import struct
import sys




################################################################################




# Default size in Mb for splitting files
DEFAULT_FILE_SIZE_MB = 10

# Encrypted file and hash extensions
EXTENSION_ENCRYPTED_FILE = ".phxf"
EXTENSION_ENCRYPTED_HASH = ".phxh"

# Git root folder is excluded from encryption
GIT_REPOSITORY_FOLDER = "%s/%s" % (os.path.dirname(os.path.abspath(sys.argv[0])), ".git")

# GITIGNORE file is excluded from encryption
GIT_REPOSITORY_GITINGNORE_FILE = "%s/%s" % (os.path.dirname(os.path.abspath(sys.argv[0])), ".gitignore")

# All README.md files are excluded from encryption (even in sub-folders)
GIT_REPOSITORY_README_FILE = "README.md"

# requirements.txt is excluded from encryption
GIT_REPOSITORY_REQUIREMENTS_FILE = "%s/%s" % (os.path.dirname(os.path.abspath(sys.argv[0])), "requirements.txt")

# cleartext folder is excluded from encryption
CLEARTEXT_FOLDER = "%s/%s" % (os.path.dirname(os.path.abspath(sys.argv[0])), "cleartext")

# HASH of the master password
MASTER_PASSWORD_ENCRYPTED_HASH = "%s%s" % ("master", EXTENSION_ENCRYPTED_HASH)




################################################################################



# AES-256-CBC constants
AES256_IV_SIZE     = 16
AES256_BLOCK_SIZE  = 32

unpad = lambda s : s[0:-ord(s[-1])]
pad = lambda s : s + (AES256_BLOCK_SIZE - len(s) % AES256_BLOCK_SIZE) * chr(AES256_BLOCK_SIZE - len(s) % AES256_BLOCK_SIZE)




################################################################################




# AES-256-CBC decryption of a string with a given password (not a key)
def aes_decrypt(ciphertext, password):
	key = aes_password_to_key(password)
	data = ciphertext.strip('\n')
	data = base64.b64decode(data)
	iv = data[:AES256_IV_SIZE]
	cipheredText = data[AES256_IV_SIZE:]
	hCrypt = AES.new(key, AES.MODE_CBC, iv)
	return unpad(hCrypt.decrypt(cipheredText))




################################################################################




# AES-256-CBC decryption of a file with a given password (not a key)
def aes_decrypt_file(in_file_name, out_filename, password):
	ret = False
	try:
		with open(in_file_name, 'rb') as fo:
			ciphertext = fo.read()
		dec = aes_decrypt(ciphertext, password)
		with open(out_filename, 'wb') as fo:
			fo.write(dec)
		ret = True
	except Exception as e:
		pass
	finally:
		return ret




################################################################################




# AES-256-CBC encryption of a string with a given password (not a key)
def aes_encrypt(plaintext, password):
	key = aes_password_to_key(password)
	data = pad(plaintext)
	iv = Random.new().read(AES256_IV_SIZE)
	hCrypt = AES.new(key, AES.MODE_CBC, iv)
	return base64.b64encode(iv + hCrypt.encrypt(data))




################################################################################




# AES-256-CBC encryption of a file with a given password (not a key)
def aes_encrypt_file(in_filename, out_filename, password):
	try:
		with open(in_filename, 'rb') as fo:
			plaintext = fo.read()
		enc = aes_encrypt(plaintext, password)
		with open(out_filename, 'wb') as fo:
			fo.write(enc)
		ret = True
	except Exception as e:
		pass
	finally:
		return ret




################################################################################




# Converts a password to an AES-256 key
def aes_password_to_key(password):
	key = hashlib.md5(password.encode('utf-8')).hexdigest()
	return key




################################################################################




# Arguments parser
def argumentsParser():
	ret = False
	parser = argparse.ArgumentParser(description = '', formatter_class = RawTextHelpFormatter)
	parser.add_argument('-e', '--encrypt', action = 'store_true', help = 'Encrypts files', required = False)
	parser.add_argument('-d', '--decrypt', action = 'store_true', help = 'Decrypts files', required = False)
	parser.add_argument('-p', '--path', type = str, help = 'Path of a folder or file to decrypt', required = False)
	parser.add_argument('-s', '--size', type = int, help = 'Split encrypted file into chunks of a specific size (Mb)\n0 = no split\ndefault = 95 Mb', required = False, default = DEFAULT_FILE_SIZE_MB)
	parser.add_argument('-c', '--clear', action = 'store_true', help = 'Remove unencrypted files after encryption\nRemove encrypted files after decryption', required = False)
	parser.add_argument('-i', '--init', action = 'store_true', help = 'Init the master password (can only be done once)', required = False)
	parser.add_argument('-u', '--update', action = 'store_true', help = 'Update the master password', required = False)
	args = parser.parse_args()
	if args.encrypt and args.decrypt:
		print_error("Options --encrypt and --decrypt cannot be used at the same time")
		ret = True
	elif (args.encrypt and args.init) or (args.decrypt and args.init) or (args.encrypt and args.update) or (args.decrypt and args.update):
		print_error("Master password cannot be set while encrypting or decrypting")
		ret = True	
	elif args.encrypt and args.path:
		print_error("Option --path can only be used with option --decrypt")
		ret = True
	if args.init and args.update:
		print_error("Master password cannot be initialized and updated at the same time")
		ret = True
	if not args.init and not args.update:
		hash_file = os.path.abspath(MASTER_PASSWORD_ENCRYPTED_HASH)
		if not is_file_exists(hash_file):
			print_error("Master password not initialized")
			ret = True
	elif args.init:
		hash_file = os.path.abspath(MASTER_PASSWORD_ENCRYPTED_HASH)
		if is_file_exists(hash_file):
			print_error("Master password already initialized")
			ret = True
	if not ret and not args.encrypt and not args.decrypt and not args.init and not args.update:
		print_error("Missing option")
		parser.print_help(sys.stderr)
		print_line_separator()
		ret = True
	if ret:
		print("\n")
		sys.exit(1)
	return args




################################################################################




# Remove temporary files generated by the program when merging chunks of a splitted file
def clean_junk_files(root):
	for f in os.listdir(root):
		path = "%s/%s" % (root, f)
		if os.path.isdir(path) and path != GIT_REPOSITORY_FOLDER and path != CLEARTEXT_FOLDER:
			clean_junk_files(path)
		elif os.path.isfile(path) and path != GIT_REPOSITORY_GITINGNORE_FILE:
			extension = "%s.tmp" % EXTENSION_ENCRYPTED_FILE
			if path.endswith(extension):
				os.remove(path)
				print_info("Deletion of junk file \"%s\"" % path)




################################################################################




# Delete files starting with a given path
def delete_files_starting_with(path):
	for filename in glob.glob(path + "*"):
		os.remove(filename)




################################################################################




# Returns file's size in bytes
def file_get_size(path):
	return os.stat(path).st_size




################################################################################




# Returns all encrypted files including encrypted files who are splitted into multiple parts
def find_encrypted_files(root):
	files = []
	for f in os.listdir(root):
		path = "%s/%s" % (root, f)
		if os.path.isdir(path) and path != GIT_REPOSITORY_FOLDER and path != CLEARTEXT_FOLDER:
			files += find_encrypted_files(path)
		elif os.path.isfile(path) and path != GIT_REPOSITORY_GITINGNORE_FILE:
			extension = os.path.splitext(path)[1]
			if extension == EXTENSION_ENCRYPTED_FILE or extension.startswith(EXTENSION_ENCRYPTED_FILE):
				files.append(path)
	return files




################################################################################




# Returns all non encrypted files
def find_non_encrypted_files(root):
	files = []
	for f in os.listdir(root):
		path = "%s/%s" % (root, f)
		if os.path.isdir(path) and path != GIT_REPOSITORY_FOLDER and path != CLEARTEXT_FOLDER:
			files += find_non_encrypted_files(path)
		elif os.path.isfile(path) and path != GIT_REPOSITORY_GITINGNORE_FILE and path != GIT_REPOSITORY_README_FILE and path != GIT_REPOSITORY_REQUIREMENTS_FILE:
			extension = os.path.splitext(path)[1]
			if not extension == EXTENSION_ENCRYPTED_FILE and not extension == EXTENSION_ENCRYPTED_HASH and not extension.startswith(EXTENSION_ENCRYPTED_FILE):
				files.append(path)
	phoenix_script = get_curent_script_path()
	if phoenix_script in files:
		files.remove(phoenix_script)
	return files




################################################################################




# Generates a file containing the AES-256-CBC encrypted SHA-256 hash of a clear text file
def generate_checksum(file_non_encrypted , password, hash_file):
	if is_file_exists(file_non_encrypted):
		if is_file_exists(hash_file):
			os.remove(hash_file)
		hash_value = sha256sum(file_non_encrypted)
		data = aes_encrypt(hash_value, password)
		fd = open(hash_file, "w+")
		fd.write(data)
		fd.close()




################################################################################




# Returns the path of the script
def get_curent_script_path():
	return os.path.abspath(sys.argv[0])




################################################################################




# Returns all files starting with a given path
def get_files_starting_by(pattern):
	return glob.glob(pattern + "*")




################################################################################




# Asks user for a password
def get_password(password_prompt = ""):
	if len(password_prompt) > 0:
		password = stdiomask.getpass(prompt = password_prompt, mask = '*')
	else:	
		password = stdiomask.getpass(prompt = 'Password : ', mask = '*')
	print("\n")
	return password




################################################################################




# Creates the cleartext folder who will be excluded from being encrypted
def init_cleartext_folder():
	if not os.path.exists(CLEARTEXT_FOLDER):
		os.mkdir(CLEARTEXT_FOLDER)




################################################################################




# Creates the GITIGNORE file
def init_gitignore():
	if is_file_exists(GIT_REPOSITORY_GITINGNORE_FILE):
		os.remove(GIT_REPOSITORY_GITINGNORE_FILE)
	fd = open(GIT_REPOSITORY_GITINGNORE_FILE, "w+")
	fd.write("#IGNORE ALL\n")
	fd.write("/**\n")
	fd.write("#ALLOW\n")
	fd.write("!/requirements.txt\n")
	fd.write("!/master.phxh\n")
	fd.write("!/.gitignore\n")
	fd.write("!*.phxf\n")
	fd.write("!*.phxf-part*\n")
	fd.write("!*.phxh\n")
	fd.write("!README.md\n")	
	fd.write("!cleartext/*\n")
	for i in range(1, 500, 1):
		fd.write("!cleartext/*%s\n" % ("/*" * i))
	fd.write("!*/\n")
	fd.close()


################################################################################




# Creates the a file containing the AES-256-CBC encrypted SHA-256 hash of the master password
# It will permits to check if the password is valid later before decrypting or encrypting new files
def init_master_password(password_prompt = ""):
	ret = False
	try:
		size_max = DEFAULT_FILE_SIZE_MB * 1000000
		password1 = get_password(password_prompt)
		password2 = get_password(password_prompt)
		if password1 == password2:	
			password_hash = sha256(password1)
			hash_file = os.path.abspath(MASTER_PASSWORD_ENCRYPTED_HASH)
			enc = aes_encrypt(password_hash, password1)
			if is_file_exists(hash_file):
				os.remove(hash_file)
			fd = open(hash_file, "w+")
			fd.write(enc)
			fd.close()
			print_success("Password initialized")
			ret = True
		else:
			print_error("Passwords mismatch")
	except Exception as e:
		pass
	finally:
		return ret




################################################################################




# Checks if the SHA-256 hash of a cleartext file is valid by comparing it to the hash
# stored in the checksum file
def is_checksum_valid(file_non_encrypted, hash_file, password):
	ret = False
	if is_file_exists(file_non_encrypted) and is_file_exists(hash_file):
		fd = open(hash_file, "rb")
		data = fd.read()
		fd.close()
		hash_value = aes_decrypt(data, password)
		hash_valid = sha256sum(file_non_encrypted)
		if hash_value == hash_valid:
			ret = True
	return ret




################################################################################




# Checks if encryption for a cleartext file is needed based on its SHA-256 hash
# compared to the hash stored in the checksum file
def is_file_encryption_needed(file_non_encrypted, password, size_max):
	ret = True
	current_hash = sha256sum(file_non_encrypted)
	dirname = os.path.dirname(file_non_encrypted)
	filename = os.path.basename(file_non_encrypted)
	file_checksum = "%s/.%s%s" % (dirname, filename, EXTENSION_ENCRYPTED_HASH)
	if is_checksum_valid(file_non_encrypted, file_checksum, password):		
		dirname = os.path.dirname(file_non_encrypted)
		filename = os.path.basename(file_non_encrypted)
		encrypted_file = '%s/.%s' % (dirname, filename + EXTENSION_ENCRYPTED_FILE)
		if size_max > 0:
			split_files = get_files_starting_by(encrypted_file + "-part")
			if len(split_files) > 0:
				tmp_file = "%s.tmp" % encrypted_file
				merge_files(split_files, tmp_file)
				size = file_get_size(tmp_file)
				os.remove(tmp_file)
				split_count = int(math.ceil(float(size / size_max)))
				cpt = 0
				for i in range(0, split_count + 1):
					split_file = "%s-part%d" % (encrypted_file, i + 1)
					if is_file_exists(split_file):
						cpt += 1
				if not is_file_exists(encrypted_file) and len(split_files) == cpt and cpt == split_count:
					ret = False
			else:
				if is_file_exists(encrypted_file):
					size = file_get_size(encrypted_file)
					split_count = int(math.ceil(float(size / size_max)))
					if split_count == 1:
						ret = False
		else:
			split_count = 1
			split_files = get_files_starting_by(encrypted_file + "-part")
			if os.path.exists(encrypted_file) and len(split_files) == 0:
				ret = False
	return ret




################################################################################




# Checks if a file exists
def is_file_exists(path):
	ret = False
	try:
		if os.path.exists(path) and os.path.isfile(path):
			ret = True
	except Exception as e:
		pass
	finally:
		return ret




################################################################################




# Check if the password used for encryption / decryption is valid
def is_master_password_valid(password):
	ret = False
	try:
		hash_file = os.path.abspath(MASTER_PASSWORD_ENCRYPTED_HASH)
		if is_file_exists(hash_file):
			fd = open(hash_file, "rb")
			data = fd.read()
			fd.close()
			password_hash = sha256(password)
			dec = aes_decrypt(data, password)
			if dec == password_hash:
				ret = True
	except Exception as e:
		pass
	finally:
		return ret




################################################################################




# Merges files into a new one
def merge_files(files, new_file):
	files = natsorted(files)
	if not is_file_exists(new_file):
		for file in files:
			with open(new_file, "ab") as fd1, open(file, "rb") as fd2:
				fd1.write(fd2.read())




################################################################################




# Banner of the program
def print_banner():
	logo = '''
                            .-==========
                         .-' O    =====
                        /___       ===
                           \_      |
_____________________________)    (_____________________________
\___________               .'      `,              ____________/
  \__________`.     |||<   `.      .'   >|||     .'__________/
     \_________`._  |||  <   `-..-'   >  |||  _.'_________/
        \_________`-..|_  _ <      > _  _|..-'_________/
           \_________   |_|  //  \\  |_|   _________/
            Ph03nix

This program encrpyts / decrypts all files in a given folder.
Encryption and decryption are done only if needed based on the hashes of the cleartext files.
All files are encrypted except the ones into the folder cleartext folder and all README.md files.
Big files can be splitted into chunks of a desired size (100Mb is the maximum file size allowed on Github).
'''
	print(Fore.GREEN + logo + Fore.RESET)
	print_line_separator()




################################################################################




# Print an error message
def print_error(string):
	print(Back.BLACK + Style.BRIGHT + Fore.RED + "[   KO   ]" + Fore.RESET + Style.RESET_ALL + Back.RESET + "  " + string, file = sys.stderr)




################################################################################




# Print an info message
def print_info(string):
	print(Back.BLACK + Style.BRIGHT + Fore.BLUE + "[  INFO  ]" + Fore.RESET + Style.RESET_ALL + Back.RESET + "  " + string)




################################################################################




# Print a line separator
def print_line_separator():
	print(Fore.YELLOW + "_" * 80 + Fore.RESET + "\n" )




################################################################################



# Print a list of info messages
def print_scoring(items):
	print("\n")
	print_line_separator()
	print("\n")
	for item in items:
		print(Back.WHITE + Style.BRIGHT + Fore.BLUE + "[  INFO  ]" + Fore.RESET + Style.RESET_ALL + Back.RESET + "  " + item)
	print("\n")



	
################################################################################




# Print an success message
def print_success(string):
	print(Back.BLACK + Style.BRIGHT + Fore.GREEN + "[   OK   ]" + Fore.RESET + Style.RESET_ALL + Back.RESET + "  " + string)




################################################################################




# Computes the SHA-256 hash of a string
def sha256(string):
	h = hashlib.sha256(string.encode('utf-8'))
	return h.hexdigest()




################################################################################




# Computes the SHA-256 hash of a file
def sha256sum(path):
	h  = hashlib.sha256()
	b  = bytearray(128 * 1024)
	mv = memoryview(b)
	with open(path, 'rb', buffering = 0) as f:
		for n in iter(lambda : f.readinto(mv), 0):
			h.update(mv[:n])
	return h.hexdigest()




################################################################################




# Splits a file into chunks of a given Mb size
def split_file(path, size):
	files = []
	dirname = os.path.dirname(path)
	filename = os.path.basename(path)
	file_number = 1
	fd1 = open(path, 'rb')
	chunk = fd1.read(size)
	while chunk:
		fd2 = open('%s/%s-part%d' % (dirname, filename, file_number), 'wb')
		fd2.write(chunk)
		fd2.close()
		file_number += 1
		chunk = fd1.read(size)
	fd1.close()




################################################################################




# Encrypt files from a root folder
def phoenix_encrypt(root, password, size_max, is_clear):
	files = find_non_encrypted_files(root)
	needed_enc_files_count = 0
	already_enc_files_count = 0
	failed_enc_files_count = 0	
	for file in files:
		if is_file_encryption_needed(file, password, size_max):
			dirname = os.path.dirname(file)
			filename = os.path.basename(file)
			encrypted_file = '%s/.%s' % (dirname, filename + EXTENSION_ENCRYPTED_FILE)
			hash_file = '%s/.%s' % (dirname, filename + EXTENSION_ENCRYPTED_HASH)
			delete_files_starting_with(encrypted_file)
			delete_files_starting_with(hash_file)
			if aes_encrypt_file(file, encrypted_file, password):
				generate_checksum(file, password, hash_file)
				if size_max > 0 and file_get_size(encrypted_file) > size_max:
					split_file(encrypted_file, size_max)
					os.remove(encrypted_file)
				if is_clear:
					os.remove(file)
					print_info("Deletion of \"%s\"" % file)
				print_success("Encryption of \"%s\"" % file)
				needed_enc_files_count += 1
			else:
				failed_enc_files_count += 1
		else:
			if is_clear:
				os.remove(file)
				print_info("Deletion of \"%s\"" % file)
			print_info("Encryption not needed for \"%s\"" % file)
			already_enc_files_count += 1
	if len(files) == 0:
		print_info("No file to encrypt")
	else:
		items = ["Files encrypted         : %s" % needed_enc_files_count, "Files already encrypted : %s" % already_enc_files_count, "Files encryption fail   : %s" % failed_enc_files_count]
		print_scoring(items)




################################################################################




# Decrypts files from a root folder
def phoenix_decrypt(root, password, is_clear):
	dec_files_count = 0
	already_dec_files_count = 0
	fail_dec_files_count = 0
	if os.path.isdir(root):
		if root[-1] == "/":
			root = root[:-1]
		files = find_encrypted_files(root)
	else:
		extension = os.path.splitext(root)[1]
		if extension == EXTENSION_ENCRYPTED_FILE:
			if is_file_exists(root):
				files = [root]
			else:
				files = get_files_starting_by("%s-part" % root)
	split_files = []
	for file in files:
		dirname = os.path.dirname(file)
		filename = os.path.basename(file)
		extension = os.path.splitext(file)[1]
		if extension == EXTENSION_ENCRYPTED_FILE:
			cleartext_file = "%s/%s" % (dirname, filename[1: - len(EXTENSION_ENCRYPTED_FILE)])
			hash_file = "%s/.%s" % (dirname, filename[1: - len(EXTENSION_ENCRYPTED_FILE)]) + EXTENSION_ENCRYPTED_HASH
			if is_file_exists(cleartext_file):
				if is_checksum_valid(cleartext_file, hash_file, password):
					print_info("Decryption not needed for \"%s\"" % file)
					already_dec_files_count += 1
				else:
					os.remove(cleartext_file)
					if aes_decrypt_file(file, cleartext_file, password):
						print_success("Decryption of \"%s\"" % file)
						dec_files_count += 1
					else:
						print_error("Decryption of \"%s\"" % file)
						fail_dec_files_count += 1
			else:
				if aes_decrypt_file(file, cleartext_file, password):
					print_success("Decryption of \"%s\"" % file)
					dec_files_count += 1
				else:
					print_error("Decryption of \"%s\"" % file)
					fail_dec_files_count += 1
			if is_clear:
				os.remove(file)
				print_info("Deletion of \"%s\"" % file)				
				os.remove(hash_file)
				print_info("Deletion of \"%s\"" % hash_file)
		elif extension.startswith(EXTENSION_ENCRYPTED_FILE):
			filename_without_extension = os.path.basename(os.path.splitext(file)[0])
			pattern = "%s/%s%s-part" % (dirname, filename_without_extension, EXTENSION_ENCRYPTED_FILE)
			found = False
			for f in split_files:
				for path in f:
					if path.startswith(pattern):
						f.append(file)
						found = True
						break
				if found:
					break
			if not found:
				split_files.append([file])
	if len(split_files):
		for files in split_files:
			count = len(files)
			filename_without_extension = os.path.basename(os.path.splitext(files[0])[0])
			dirname = os.path.dirname(files[0])
			pattern = "%s/%s%s" % (dirname, filename_without_extension, EXTENSION_ENCRYPTED_FILE)
			cpt = 0
			chunks = []
			for i in range(count, 0, -1):
				split_file = "%s-part%d" % (pattern, i)
				if is_file_exists(split_file):
					chunks.append(split_file)
					cpt += 1
			if cpt == count:
				files.sort()
				if is_file_exists(pattern):
					os.remove(pattern)
				merge_files(files, pattern)
				cleartext_file = "%s/%s" % (dirname, filename_without_extension[1:])
				hash_file = "%s/.%s" % (dirname, os.path.basename(pattern)[1: - len(EXTENSION_ENCRYPTED_FILE)]) + EXTENSION_ENCRYPTED_HASH
				if is_file_exists(cleartext_file):
					if is_checksum_valid(cleartext_file, hash_file, password):
						os.remove(pattern)
						print_info("Decryption not needed for \"%s\"" % pattern)
						already_dec_files_count += 1
					else:
						os.remove(cleartext_file)
						if aes_decrypt_file(pattern, cleartext_file, password):
							os.remove(pattern)
							print_success("Decryption of \"%s\"" % pattern)
							dec_files_count += 1
						else:
							print_error("Decryption of \"%s\"" % pattern)
							fail_dec_files_count += 1		
				else:
					if aes_decrypt_file(pattern, cleartext_file, password):
						os.remove(pattern)
						print_success("Decryption of \"%s\"" % pattern)
						dec_files_count += 1
					else:
						print_error("Decryption of \"%s\"" % pattern)
						fail_dec_files_count += 1 
				if is_clear:
					for chunk in chunks:
						os.remove(chunk)
						print_info("Deletion of \"%s\"" % chunk)
					os.remove(hash_file)

	if len(files) == 0:
		print_info("No file to decrypt")
	else:
		items = ["Files decrypted         : %s" % dec_files_count, "Files already decrypted : %s" % already_dec_files_count, "Files decryption fail   : %s" % fail_dec_files_count]
		print_scoring(items)		



################################################################################




# MAIN function
if __name__ == "__main__":
	print_banner()
	init_gitignore()
	init_cleartext_folder()
	args = argumentsParser()
	cwd = os.path.abspath(".")
	clean_junk_files(cwd)
	if args.encrypt:
		password = get_password()
		if is_master_password_valid(password):
			size_max = args.size * 1000000
			phoenix_encrypt(cwd, password, size_max, args.clear)
		else:
			print_error("Invalid password")
	elif args.decrypt:
		password = get_password()
		if is_master_password_valid(password):
			if args.path is None:			
				phoenix_decrypt(cwd, password, args.clear)
			else:
				phoenix_decrypt(args.path, password, args.clear)
		else:
			print_error("Invalid password")			
	elif args.init:
		init_master_password()
	elif args.update:
		password = get_password()
		if is_master_password_valid(password):
			phoenix_decrypt(cwd, password, True)
			if init_master_password("New Password : "):
				size_max = DEFAULT_FILE_SIZE_MB * 1000000
				phoenix_encrypt(cwd, password, size_max, False)
		else:
			print_error("Invalid password")
	print("\n")