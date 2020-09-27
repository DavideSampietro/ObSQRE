import attestation
from subtol_cli import *
import sys

# for object serialization
import pickle

#URL_BASE = 'http://compilergroup-srv.elet.polimi.it:49000'
URL_BASE = 'http://127.0.0.1:49000'
SPID = 'SPID-ID'
# subtol specific ack/nack strings for msg4
ACK_STRING = b'trusted subtol enclave'
NACK_STRING = b'untrusted enclave'

# suppress traceback on exceptions!
sys.tracebacklimit = None

if len(sys.argv) > 2:
	print('usage: client [session-dumpfile]')
	sys.exit()

# restore session
elif len(sys.argv) == 2:
	dumpfile = open(sys.argv[1], "rb")
	subtol = pickle.load(dumpfile)
	subtol.close_context = True

# create new session
elif len(sys.argv) == 1:
	# create attestation context
	att = attestation.AttestationContext(SPID)

	# perform the attestation flow
	att.init_session(URL_BASE)
	print('[OK] Init Session')
	att.derive_SMK()
	att.send_msg2(URL_BASE)
	print('[OK] Msg2 Exchange')
	att.check_msg3(URL_BASE)
	att.remote_attestation(URL_BASE)
	print('[OK] Remote Attestation')
	att.derive_session_keys()

	# print enclave details
	print('[INFO] MR_ENCLAVE:' + att.MRENCLAVE)
	print('[INFO] ISV PID:' + hex(att.PID))
	print('[INFO] ISV SVN:' + hex(att.SVN))

	# prompt user whether he trusts the printed values, which I will always :)
	att.final_handshake(URL_BASE, ACK_STRING)
	print('[OK] Handshake\n');

	subtol = SubtolCli(URL_BASE, att)

# start subtol-cli
subtol.cli()
