import attestation

import json
import requests
import base64

import readline
import sys
import os
import string
import pickle

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.backends import openssl
from cryptography.exceptions import InvalidTag

from termcolor import colored

# select the backend for performing crypto stuff (obviously, openssl!)
OPENSSL_BACKEND = openssl.backend

class ContextRestore:
	def __init__(self, att):
		self.SK = att.SK
		self.SESSION_ID = att.SESSION_ID
		self.PID = att.PID
		self.SVN = att.SVN
		self.MRENCLAVE = att.MRENCLAVE

class SubtolCli:
	
	def __init__(self, url_base, context):
		self.url_base = url_base
		
		# context variables
		self.context = ContextRestore(context)
		self.close_context = True
		
		# ubiquitously required
		self.session_cookie = {'Cookie' : 'session-id=' + self.context.SESSION_ID}
		
		# to map characters to integers
		self.mapstr = None
		self.mapper = None
		
		# for suffix array
		self.start = 0
		self.end = 0
		
		# to generate meaningful bench
		self.oram_type = None
		self.filename = None

	# subtol-cli commands

	def __clear(self, args):
		os.system('clear')

	def __help(self, args):
		print('Recognized commands:\n')
		print('STATUS:')
		print('poll\t\t check status of the session')
		print('info\t\t prints enclave info')
		print('\nSETUP:')
		print('config\t\t configure enclave parameters')
		print('load\t\t init the ORAM for substring search with file')
		print('dump\t\t dump the session to restore it after client is closed')
		print('close\t\t closes the session (invoked along with exit if not dumped)')
		print('\nQUERY:')
		print('query\t\t query the subtol server')
		print('benchmark\t automatically query to gather benchmarks')
		print('suffix\t\t progressively fetch portions of the suffix array')
		print('\nCONSOLE:')
		print('clear\t\t clear the screen')
		print('help\t\t print this help')
		print('exit\t\t close console')
	
	def __info(self, args):
		print('MR_ENCLAVE:' + self.context.MRENCLAVE)
		print('ISV PID:' + hex(self.context.PID))
		print('ISV SVN:' + hex(self.context.SVN))

	def __poll(self, args):
		if len(args) == 0:
			req = requests.get(self.url_base + '/poll', headers=self.session_cookie)
			
			if req.status_code == 404:
				print('Error: attestation context not found')
			elif req.status_code == 409:
				print('Context existing but busy')
			elif req.status_code == 200:
				print('Context READY')
			else:
				print(req.json()['error'])
			
		else:
			print('poll requires no parameters')
	
	def __print_config_help(self):
		print('config <oram_type> <Z> <stash> [S A] [rec_map_size] [sa_block_size]\n')
		print('oram_type\t [circuit | ring | path]')
		print('Z\t\t number of valid records per bucket')
		print('stash\t\t size of the stash')
		print('[S]\t\t only for RingORAM - number of dummy blocks per bucket')
		print('[A]\t\t only for RingORAM - eviction rate')
		print('[rec_map_size]\t #pointers into recursive position map block - default 4')
		print('[sa_block_size]\t #suffix-array entries into each block - default 256')
	
	def __load(self, args):
		if len(args) != 2:
			print('load <remote_filename> <pbkdf2_pwd>\n')
			print('pbkdf2_pwd\t at most 64 printable ASCII characters')
			return
		
		try:
			mapfile = open(args[0] + '.map', 'r')
			self.mapstr = mapfile.read()
			mapfile.close()
		except OSError:
			print('No .map file found for the specified index')
			return
		
		padded_pwd = bytearray(64) # 64 \x00 bytes
		pwd_bytes = args[1].encode("ascii", errors="ignore")
		
		for i in range(0, min(64, len(pwd_bytes))):
			padded_pwd[i] = pwd_bytes[i]
		
		# encrypt such data
		iv = os.urandom(12)
		
		gcm = AESGCM(self.context.SK)
		enc_pwd_mac = gcm.encrypt(iv, bytes(padded_pwd), None)
		# get mac
		mac = enc_pwd_mac[-16:]
		# get encrypted password
		enc_pwd = enc_pwd_mac[0:64]
		
		# append filename
		payload = enc_pwd + bytes(args[0], encoding='utf-8')
		
		# build json
		msg = {}
		msg['iv'] = base64.b64encode(iv).decode('utf-8')
		msg['mac'] = base64.b64encode(mac).decode('utf-8')
		msg['payload'] = base64.b64encode(payload).decode('utf-8')
		
		jmsg = json.dumps(msg)
		req = requests.post(self.url_base + '/load', headers=self.session_cookie, data=jmsg)
		
		if req.status_code != 202:
			print(req.json()['error'])
		else:
			self.filename = args[0]
	
	def __benchmark(self, args):
		if len(args) != 2:
			print('benchmark <string> <reps>')
			return
		
		try:
			reps = int(args[1])
		except ValueError:
			print('\nError while parsing rec_map_size')
			return
		
		for i in range(0, reps):
			self.__query(args[0:1])
	
	def __suffix(self, args):
		if len(args) != 0:
			print('suffix requires no args')
			return
		
		req = requests.get(self.url_base + '/suffix', headers=self.session_cookie)
		
		
		if req.status_code != 200:
			print(req.json()['error'])
		else:
			iv = base64.b64decode(req.json()['iv'])
			data = base64.b64decode(req.json()['payload']) + base64.b64decode(req.json()['mac'])
		
			gcm = AESGCM(self.context.SK)
			
			try:
				sa = gcm.decrypt(iv, data, None)
			except InvalidTag:
				print('MAC mismatch')
				return
			
			suffix = list()
			
			for i in range(0, len(sa) // 4):
				suffix.append(int.from_bytes(sa[i*4:(i+1)*4], "little", signed=True))
			
			idx1 = self.start % len(suffix)
			self.start = self.start - idx1
			
			if self.end - self.start >= len(suffix):
				idx2 = len(suffix)
			else:
				if self.end == -1:
					idx2 = -1
				else:
					idx2 = self.end % len(suffix)
					self.end = -1
			
			self.start = self.start + len(suffix)
			
			for i in range(0, len(suffix)):
				if i > idx2:
					print('< ' + str(suffix[i]))
				elif i < idx1:
					print('> ' + str(suffix[i]))
				else:
					print(str(suffix[i]))
	
	def __query(self, args):
		if len(args) != 1:
			print('query <string>')
			return
		
		if self.mapper == None:
			if self.mapstr != None:
				self.mapper = lambda x: self.mapstr.find(x).to_bytes(1, byteorder='little', signed=True)
			else:
				print('Cannot query the server: no character map defined')
				return
		
		temp = b''.join(list(map(self.mapper, args[0])))
		
		# encrypt query
		iv = os.urandom(12)
		
		gcm = AESGCM(self.context.SK)
		enc_query_mac = gcm.encrypt(iv, temp, None)
		# get mac
		mac = enc_query_mac[-16:]
		# get encrypted password
		enc_query = enc_query_mac[0:-16]
		
		# build json
		msg = {}
		msg['iv'] = base64.b64encode(iv).decode('utf-8')
		msg['mac'] = base64.b64encode(mac).decode('utf-8')
		msg['payload'] = base64.b64encode(enc_query).decode('utf-8')
		
		jmsg = json.dumps(msg)
		req = requests.get(self.url_base + '/substring', headers=self.session_cookie, data=jmsg)
		
		if req.status_code != 200:
			print(req.json()['error'])
		
		else:
			iv = base64.b64decode(req.json()['iv'])
			data = base64.b64decode(req.json()['payload'])
			
			timediff = data[8:16]
			timediff = int.from_bytes(timediff, byteorder='little', signed=True)
			
			data = data[0:8] + base64.b64decode(req.json()['mac'])
			#data = base64.b64decode(req.json()['payload']) + base64.b64decode(req.json()['mac'])

			try:
				out = gcm.decrypt(iv, data, None)
			except InvalidTag:
				print('MAC mismatch')
				return
			
			start = out[0:4]
			end = out[4:8]
			
			start = int.from_bytes(start, byteorder='little', signed=True)
			end = int.from_bytes(end, byteorder='little', signed=True)
			
			self.start = start
			self.end = end
			
			print(self.filename + ',' + self.oram_type + ',' + str(len(args[0])) + ',' + str(start) + ',' + str(end) + ',' + str(timediff))
	
	def __config(self, args):
		if len(args) < 3:
			self.__print_config_help()
			print('\nMissing arguments')
			return
		
		oram_type = -1
		
		if args[0] == 'circuit':
			oram_type = 0
		elif args[0] == 'ring':
			oram_type = 1
		elif args[0] == 'path':
			oram_type = 2
		else:
			self.__print_config_help()
			print('\nWrong ORAM type')
			return
		
		Z = -1
		stash = -1
		
		try:
			Z = int(args[1])
			stash = int(args[2])
		except ValueError:
			self.__print_config_help()
			print('\nError parsing integers (Z and/or stash)')
			return
		
		# they will end in the final struct anyways...
		S = 0
		A = 0
		
		remainder_args = len(args)
		
		if oram_type == 1 and len(args) >= 5:
			remainder_args = remainder_args - 5
			
			try:
				S = int(args[3])
				A = int(args[4])
			except ValueError:
				self.__print_config_help()
				print('\nError parsing integers (S and/or A)')
				return
		elif oram_type == 1 and len(args) < 5:
			self.__print_config_help()
			print('\nMissing parameters for RingORAM')
			return
		else:
			remainder_args = remainder_args - 3
		
		if remainder_args > 2:
			self.__print_config_help()
			print('\nToo many arguments')
			return
		
		# default additional arguments
		csize = 4
		sa_block = 16
		
		if remainder_args > 0:
			try:
				csize = int(args[len(args) - remainder_args])
			except ValueError:
				print('\nError while parsing rec_map_size')
				return
			
			remainder_args = remainder_args - 1
		
		if remainder_args > 0:
			try:
				sa_block = int(args[len(args) - remainder_args])
			except ValueError:
				print('\nError while parsing sa_block_size')
				return
			
			remainder_args = remainder_args - 1
		
		# now I serialize (everything is unsigned integer)
		blob = bytearray()
		blob += oram_type.to_bytes(4, byteorder='little', signed=False)
		blob += Z.to_bytes(4, byteorder='little', signed=False)
		blob += stash.to_bytes(4, byteorder='little', signed=False)
		blob += S.to_bytes(4, byteorder='little', signed=False)
		blob += A.to_bytes(4, byteorder='little', signed=False)
		blob += csize.to_bytes(4, byteorder='little', signed=False)
		blob += sa_block.to_bytes(4, byteorder='little', signed=False)
		
		s_blob = bytes(blob)
		
		conf = {}
		conf['payload'] = base64.b64encode(s_blob).decode('utf-8')
		empty_iv = bytes(12)
		conf['iv'] = base64.b64encode(empty_iv).decode('utf-8')
		
		# sign message
		maccer = cmac.CMAC(AES(self.context.SK), OPENSSL_BACKEND)
		maccer.update(s_blob)
		mac = maccer.finalize()
		conf['mac'] = base64.b64encode(mac).decode('utf-8')
		
		jconf = json.dumps(conf)
		req = requests.post(self.url_base + '/configure', headers=self.session_cookie, data=jconf)
		
		if req.status_code != 200:
			print(req.json()['error'])
		else:
			self.oram_type = args[0] + 'Z' + str(Z)
	
	def __exit(self, args):
		if self.close_context:
			req = requests.delete(self.url_base + '/close', headers=self.session_cookie)
		
			if req.status_code != 200:
				print(req.json()['error'])
	
	def __dump(self, args):
		if len(args) > 1:
			print('dump [session-dump]')
			print('If session dump is not provided, a truncated version of the SESSION ID will be used')
			return

		elif len(args) == 1:
			dumpfile = open(args[0], "wb")
		else:
			dumpfile = open(self.context.SESSION_ID[0:10], "wb")
		
		# cannot pickle lambdas
		map_dump = self.mapper
		self.mapper = None

		pickle.dump(self, dumpfile)
		dumpfile.close()
		
		self.mapper = map_dump
		
		self.close_context = False
	
	# dictionary of commands
	# mangled name of "private" methods
	command_dict = {
		"config": _SubtolCli__config,
		"clear": _SubtolCli__clear,
		"poll": _SubtolCli__poll,
		"load": _SubtolCli__load,
		"query": _SubtolCli__query,
		"benchmark": _SubtolCli__benchmark,
		"info": _SubtolCli__info,
		"help": _SubtolCli__help,
		"close": _SubtolCli__exit,
		"dump": _SubtolCli__dump,
		"suffix": _SubtolCli__suffix,
		"exit": None
	}

	# interface
	
	def cli(self):
		while True:
			prompt = input(colored('subtol', 'green') + ':~$ ')
			
			argv = prompt.split()
			if len(argv) == 0:
				continue
			
			command = SubtolCli.command_dict.get(argv[0], None)
			args = argv[1:]
			
			# manage exit
			if argv[0] == 'exit':
				if(len(args) == 0):
					self.__exit([])
					break
				else:
					print('Exit doesn\'t require any argument')
					continue
			
			if command != None:
				command(self, args)
			else:
				print('Wrong command\n')
				self.__help(args)
	
	def xc(self, cline):
		argv = cline.split()
		command = SubtolCli.command_dict.get(argv[0], None)
		args = argv[1:]
			
		if command != None:
			command(self, args)
	
	def qpoll(self):
		req = requests.get(self.url_base + '/poll', headers=self.session_cookie)
		return req.status_code
