# python crypto library (https://cryptography.io)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.backends import openssl

# python SSL library (https://pyOpenSSL.org)
import OpenSSL

# python netlibs
import requests
import base64
import json
import urllib

# python default
import os


# select the backend for performing crypto stuff (obviously, openssl!)
OPENSSL_BACKEND = openssl.backend
# select the P-256 curve involved in the ECDHE process with SGX
P_256 = ec.SECP256R1()


# Intel root certificate for attestation services
INTEL_ROOT_CA = """
-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----
"""


class AttestationException(Exception):
    def __init__(self, msg):
        super(AttestationException, self).__init__(msg)


class AttestationContext:
    # dummy ec private key in order to comply to the protocol
    common_ec_private_key_hex = 'c6be22605aa47bf76567931eba55d37d2af2b67e08e6a0523776937b6707a129'
    # other constants...
    INTEL_IAS = 'https://api.trustedservices.intel.com/sgx/dev'
    # Intel's certificate chain Common Names
    INTEL_SIGN_CN = 'Intel SGX Attestation Report Signing'
    INTEL_ROOT_CA_CN = 'Intel SGX Attestation Report Signing CA'

    def __init__(self, spid):
        # create session for IAS
        self.ias_session = requests.Session()

        with open("{}.key".format(spid)) as spidkey:
            subscription_key = spidkey.read().splitlines()[0]
            self.ias_session.headers.update({'Ocp-Apim-Subscription-Key': subscription_key})

        # create private key over P-256
        self.ec_client_priv = ec.generate_private_key(P_256, OPENSSL_BACKEND)
        # now initialize the rest of the key material
        self.ec_server_pub = None
        self.shared_secret = None
        self.KDK = None             # Key-Derivation Key
        self.SMK = None             # Sigma Protocol Key
        self.VK  = None             # Verification Key
        self.SK  = None             # Symmetric Key
        self.MK  = None             # Master Key
        # other parameters
        self.SPID = spid            # Service Provider ID
        self.MRENCLAVE = None       # Enclave Identity
        self.PID = None             # Enclave Product ID
        self.SVN = None             # Enclave Security Number (i.e. revision)
        self.GID = None             # EPID Group ID to retrieve the SigRL
        # session parameters
        self.SESSION_ID = None
        self.IAS_NONCE = None
        # other help variables
        self.ga_x = None
        self.ga_y = None
        self.gb_x = None
        self.gb_y = None
        self.jmsg3 = None
        self.quote_bytes = None

    def init_session(self, url_base):
        req = requests.get(url_base + '/start_session')

        if(req.status_code == 200):
            # dump your session-id
            self.SESSION_ID = req.cookies['session-id']

            jmsg1 = req.json()

            # check that the given extended epid group id is 0, the only one supported
            # by Intel Attestation Service
            extended_egid = base64.b64decode(jmsg1['msg0']['extended_epid_group_id'])
            extended_egid = int.from_bytes(extended_egid, byteorder='little', signed=False)
            if extended_egid != 0:
                self.__close_session(url_base)
                raise AttestationException('Extended Epid Group ID error: IAS only supports 0x0 while given ' + str(extended_egid))

            # now dump the server ecdh public key
            srv_pubkey_coords = jmsg1['msg1']['sgx_server_ec_pubkey']

            self.ga_x = base64.b64decode(srv_pubkey_coords['x_coord'])
            srv_x = int.from_bytes(self.ga_x, byteorder='little', signed=False)

            self.ga_y = base64.b64decode(srv_pubkey_coords['y_coord'])
            srv_y = int.from_bytes(self.ga_y, byteorder='little', signed=False)

            self.ec_server_pub = ec.EllipticCurvePublicNumbers(srv_x, srv_y, P_256).public_key(OPENSSL_BACKEND)

            # now perform key exchange
            self.shared_secret = self.ec_client_priv.exchange(ec.ECDH(), self.ec_server_pub)
            # invert the endianness of the shared secred
            self.shared_secret = self.shared_secret[::-1]

            # dump gid
            self.GID = base64.b64decode(jmsg1['msg1']['sgx_epid_group_id'])
            self.GID = self.GID[::-1]
            self.GID = self.GID.hex()

        else:
            error_msg = 'Status code: ' + str(req.status_code) + ': ' + req.json()['error']
            raise AttestationException(error_msg)

    def derive_SMK(self):
        # once the shared secret has been established, the KDK is:
        # AES-128 CMAC of shared secret with key 0x00..00
        mac = cmac.CMAC(AES(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), OPENSSL_BACKEND)
        mac.update(self.shared_secret)
        self.KDK = mac.finalize()

        # derive the SMK using KDK as a key over text b'\x01SMK\x00\x80\x00'
        mac = cmac.CMAC(AES(self.KDK), OPENSSL_BACKEND)
        mac.update(b'\x01SMK\x00\x80\x00')
        self.SMK = mac.finalize()

        # derive VK as the CMAC using KDK of b'\x01VK\x00\x80\x00'
        mac = cmac.CMAC(AES(self.KDK), OPENSSL_BACKEND)
        mac.update(b'\x01VK\x00\x80\x00')
        self.VK = mac.finalize()

    def send_msg2(self, url_base):
        # build the message field by field...
        msg2 = {}
        blob = bytearray()

        self.__msg2_gb(msg2, blob)
        self.__msg2_spid(msg2, blob)
        self.__msg2_qtkdf(msg2, blob)
        self.__msg2_sign(msg2, blob)
        self.__msg2_mac(msg2, blob)
        self.__msg2_sigrl(msg2)

        jmsg2 = json.dumps(msg2)

        # send the message
        s_cookie = {'Cookie' : 'session-id=' + self.SESSION_ID}
        req = requests.post(url_base + '/attestation/1', headers=s_cookie, data=jmsg2)

        if req.status_code == 200:
            self.jmsg3 = req.json()
        else:
            self.__close_session(url_base)
            error_msg = 'Status code: ' + str(req.status_code) + ': ' + req.json()['error']
            raise AttestationException(error_msg)

    def check_msg3(self, url_base):
        # check the server public key
        received_ga_x_bytes = base64.b64decode(self.jmsg3['sgx_server_ec_pubkey']['x_coord'])
        received_ga_y_bytes = base64.b64decode(self.jmsg3['sgx_server_ec_pubkey']['y_coord'])
        received_ga_x = int.from_bytes(received_ga_x_bytes, byteorder='little', signed=False)
        received_ga_y = int.from_bytes(received_ga_y_bytes, byteorder='little', signed=False)

        stored_ga_x = int.from_bytes(self.ga_x, byteorder='little', signed=False)
        stored_ga_y = int.from_bytes(self.ga_y, byteorder='little', signed=False)

        # delete variables, no more needed!
        self.ga_x = None
        self.ga_y = None

        if stored_ga_x != received_ga_x or stored_ga_y != received_ga_y:
            self.__close_session(url_base)
            raise AttestationException('In MSG3: mismatch in the server EC public key')

        # check the CMAC
        self.quote_bytes = base64.b64decode(self.jmsg3['quote'])

        blob = bytearray()
        blob += received_ga_x_bytes
        blob += received_ga_y_bytes
        blob += base64.b64decode(self.jmsg3['security_prop'])
        blob += self.quote_bytes

        mac = cmac.CMAC(AES(self.SMK), OPENSSL_BACKEND)
        mac.update(bytes(blob))
        cmac_m = mac.finalize()

        cmac_m_received = base64.b64decode(self.jmsg3['cmac_m'])

        if not AttUtils.bytes_equal(cmac_m, cmac_m_received):
            self.__close_session(url_base)
            raise AttestationException('In MSG3: mismatch in the CMAC of the received message')

        # check the SHA256 in the sgx_report_data_t
        # built from the blob (ga | gb | VK)
        blob = bytearray()
        blob += received_ga_x_bytes
        blob += received_ga_y_bytes
        blob += self.gb_x
        blob += self.gb_y
        blob += self.VK

        # delete variables, no more needed!
        self.gb_x = None
        self.gb_y = None

        hasher = Hash(SHA256(), OPENSSL_BACKEND)
        hasher.update(bytes(blob))
        vk_hash = hasher.finalize()

        if not AttUtils.bytes_equal(vk_hash, self.quote_bytes[432-64:432-32]):
            self.__close_session(url_base)
            # Python Eater
            raise AttestationException('In MGS3: mismatch in the SHA256 of (Ga|Gb|VK)')

    def remote_attestation(self, url_base):
        attestation_json = {}
        attestation_json['isvEnclaveQuote'] = self.jmsg3['quote']

        self.IAS_NONCE = AttUtils.gen_rand_string(32)
        attestation_json['nonce'] = self.IAS_NONCE

        quote_req = self.ias_session.post(AttestationContext.INTEL_IAS + '/attestation/v4/report',\
            json=attestation_json, headers={'Content-Type':'application/json'})

        if quote_req.status_code != 200:
            self.__close_session(url_base)

            code = quote_req.status_code
            error_msg = 'IAS status code: ' + str(code) + ': '

            if code == 401:
                error_msg += 'Unauthorized'
            elif code == 404:
                error_msg += 'EGID not found'
            elif code == 500:
                error_msg += 'Internal server error'
            elif code == 503:
                error_msg += 'Everyone in the world doing a thesis about SGX, server overloaded'
            else:
                error_msg += '???'

            raise AttestationException(error_msg)

        header = quote_req.headers

        text_pem_chain = urllib.parse.unquote(header['x-iasreport-signing-certificate'])
        cert_chain = text_pem_chain.split('-----END CERTIFICATE-----\n')
        cert_chain.pop() # delete last dummy ('') entry

        for i in range(0, len(cert_chain)):
            cert_chain[i] = cert_chain[i] + '-----END CERTIFICATE-----'

        x509_chain = list()

        # now deserialize the certificates in PEM
        for cert in cert_chain:
            x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, bytes(cert, 'utf-8'))
            # isolate common names of issuer and subject
            common_name = list(filter(lambda x: x[0] == b'CN', x509cert.get_subject().get_components())).pop()[1].decode('utf-8')
            issuer_name = list(filter(lambda x: x[0] == b'CN', x509cert.get_issuer().get_components())).pop()[1].decode('utf-8')
            if common_name == AttestationContext.INTEL_SIGN_CN and issuer_name == AttestationContext.INTEL_ROOT_CA_CN:
                x509_chain.append(x509cert)

        if len(x509_chain) != 1:
            self.__close_session(url_base)
            raise AttestationException('Malformed X-IASReport-Signing-Certificate header')

        signing_cert = x509_chain.pop()

        # build a trust store containing the HARDCODED Intel Attestation Service Root CA certificate
        intel_root_ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, bytes(INTEL_ROOT_CA, 'utf-8'))
        trust_store = OpenSSL.crypto.X509Store()
        trust_store.add_cert(intel_root_ca)

        try:
            verifier = OpenSSL.crypto.X509StoreContext(trust_store, signing_cert)
            verifier.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError:
            self.__close_session(url_base)
            raise AttestationException('Failed to verify the signer identity into X-IASReport-Signing-Certificate')

        # now check the signature inside the header
        try:
            OpenSSL.crypto.verify(signing_cert, base64.b64decode(header['x-iasreport-signature']), quote_req.content, 'sha256')
        except Exception:
            self.__close_session(url_base)
            raise AttestationException('Failed to verify the signature inside X-IASReport-Signature')

        r_json = quote_req.json()

        # check the quote body of the report
        if not AttUtils.bytes_starts_with(self.quote_bytes, base64.b64decode(r_json['isvEnclaveQuoteBody'])):
            self.__close_session(url_base)
            raise AttestationException('Wrong quote returned by Intel IAS!')

        # check the provided nonce
        if r_json['nonce'] != self.IAS_NONCE:
            self.__close_session(url_base)
            raise AttestationException('Mismatching nonce, possible replay attack')

        # check if everything is OK
        if r_json['isvEnclaveQuoteStatus'] != 'OK':
            if r_json['isvEnclaveQuoteStatus'] == 'GROUP_OUT_OF_DATE':
                print('Group out of date pass through...')
            else:
                self.__close_session(url_base)
                error_msg = 'Attestation report not OK: IAS replied \"' + r_json['isvEnclaveQuoteStatus'] + '\"'
                raise AttestationException(error_msg)

        self.MRENCLAVE = self.quote_bytes[48+64:48+64+32].hex()
        self.PID = int.from_bytes(self.quote_bytes[48+256:48+256+2], byteorder='little')
        self.SVN = int.from_bytes(self.quote_bytes[48+258:48+258+2], byteorder='little')

        # no more needed!!!
        self.quote_bytes = None
        self.jmsg3 = None

    def derive_session_keys(self):
        mac = cmac.CMAC(AES(self.KDK), OPENSSL_BACKEND)
        mac.update(b'\x01MK\x00\x80\x00')
        self.MK = mac.finalize()

        mac = cmac.CMAC(AES(self.KDK), OPENSSL_BACKEND)
        mac.update(b'\x01SK\x00\x80\x00')
        self.SK = mac.finalize()

    def final_handshake(self, url_base, auth_bytes):
        maccer = cmac.CMAC(AES(self.SK), OPENSSL_BACKEND)
        maccer.update(auth_bytes)
        mac = maccer.finalize()

        iv = bytearray(12)

        # assemble the json
        msg4 = {};
        msg4['iv'] = base64.b64encode(iv).decode('utf-8')
        msg4['payload'] = base64.b64encode(auth_bytes).decode('utf-8')
        msg4['mac'] = base64.b64encode(mac).decode('utf-8')

        jmsg4 = json.dumps(msg4)

        # send the message
        s_cookie = {'Cookie' : 'session-id=' + self.SESSION_ID}
        req = requests.post(url_base + '/attestation/2', headers=s_cookie, data=jmsg4)

        if req.status_code != 200:
            error_msg = 'Status code: ' + str(req.status_code) + ': ' + req.json()['error']
            raise AttestationException(error_msg)


    def __close_session(self, url_base):
        s_cookie = {'Cookie' : 'session-id=' + self.SESSION_ID}
        req = requests.delete(url_base + '/attestation', headers=s_cookie)

        if req.status_code == 200:
            # generate new key
            self.ec_client_priv = ec.generate_private_key(P_256, OPENSSL_BACKEND)
            # delete key material
            self.ec_server_pub = None
            self.shared_secret = None
            self.KDK = None
            self.SMK = None
            self.VK  = None
            self.SK  = None
            self.MK  = None
            # delete temp variables (if present)
            self.ga_x = None
            self.ga_y = None
            self.gb_x = None
            self.gb_y = None
            self.jmsg3 = None
            self.quote_bytes = None
        else:
            error_msg = 'Status code: ' + str(req.status_code) + ': ' + req.json()['error']
            raise AttestationException(error_msg)

    def __msg2_gb(self, msg2, blob):
        ec_client_pub = self.ec_client_priv.public_key().public_numbers()
        self.gb_x = ec_client_pub.x.to_bytes(32, byteorder='little')
        self.gb_y = ec_client_pub.y.to_bytes(32, byteorder='little')

        # accumulate into blob for signature
        blob += self.gb_x
        blob += self.gb_y

        # create entry in the message 2 dictionary
        client_pubkey = {}
        client_pubkey['x_coord'] = base64.b64encode(self.gb_x).decode('utf-8')
        client_pubkey['y_coord'] = base64.b64encode(self.gb_y).decode('utf-8')
        msg2['sgx_client_ec_pubkey'] = client_pubkey

    def __msg2_spid(self, msg2, blob):
        spid_bytes = bytes.fromhex(self.SPID)
        blob += spid_bytes
        msg2['spid'] = base64.b64encode(spid_bytes).decode('utf-8')

    def __msg2_qtkdf(self, msg2, blob):
        # append quote type - 0x0 is unlinked quote
        blob += b'\x00\x00'
        # append key derivation function - 0x1 is the default Key Derivation Function
        blob += b'\x01\x00'

        msg2['quote_type'] = 0
        msg2['kdf'] = 1

    def __msg2_sign(self, msg2, blob):
        priv_sig_key_bytes = bytes().fromhex(AttestationContext.common_ec_private_key_hex)
        priv_sig_key_int = int.from_bytes(priv_sig_key_bytes, byteorder='little', signed=False)
        common_ec_key = ec.derive_private_key(priv_sig_key_int, P_256, OPENSSL_BACKEND)

        sig_material = bytearray()
        sig_material += self.gb_x
        sig_material += self.gb_y
        sig_material += self.ga_x
        sig_material += self.ga_y

        # generate signature
        signature_der = common_ec_key.sign(bytes(sig_material), ec.ECDSA(SHA256()))
        r, s = decode_dss_signature(signature_der)
        sig_x = r.to_bytes(32, byteorder='little')
        sig_y = s.to_bytes(32, byteorder='little')
        # append to the binary blob to me CMACed
        blob += sig_x
        blob += sig_y
        # append to msg2
        sig_sp = {}
        sig_sp['x_coord'] = base64.b64encode(sig_x).decode('utf-8')
        sig_sp['y_coord'] = base64.b64encode(sig_y).decode('utf-8')
        msg2['sig_sp'] = sig_sp

    def __msg2_mac(self, msg2, blob):
        mac = cmac.CMAC(AES(self.SMK), OPENSSL_BACKEND)
        mac.update(bytes(blob))
        cmac_smk = mac.finalize()
        msg2['cmac_a'] = base64.b64encode(cmac_smk).decode('utf-8')

    def __msg2_sigrl(self, msg2):
        sigrl = self.ias_session.get(AttestationContext.INTEL_IAS + '/attestation/v4/sigrl/' + self.GID)

        if sigrl.status_code == 200:
            if len(sigrl.text) == 0:
                msg2['sigrl_size'] = 0
                msg2['sigrl'] = None
            else:
                sig_size = (len(sigrl.text) // 4) * 3
                if sigrl.text[-1] == '=':
                    sig_size = sig_size - 1
                if sigrl.text[-2] == '=':
                    sig_size = sig_size - 1
                msg2['sigrl_size'] = sig_size
                msg2['sigrl'] = sigrl.text

        else:
            code = sigrl.status_code
            error_msg = 'IAS status code: ' + str(code) + ': '

            if code == 401:
                error_msg += 'Unauthorized'
            elif code == 404:
                error_msg += 'EGID not found'
            elif code == 500:
                error_msg += 'Internal server error'
            elif code == 503:
                error_msg += 'Everyone in the world doing a thesis about SGX, server overloaded'
            else:
                error_msg += '???'

            raise AttestationException(error_msg)


class AttUtils:
    random_string_feed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?/@#!$%"

    def bytes_starts_with(seq1, seq2):
        if len(seq1) < len(seq2):
            return False
        else:
            for i in range(0, len(seq2)):
                if seq1[i] != seq2[i]:
                    return False
            return True

    def bytes_equal(seq1, seq2):
        if len(seq1) != len(seq2):
            return False
        else:
            for i in range(0, len(seq1)):
                if seq1[i] != seq2[i]:
                    return False
            return True

    def gen_rand_string(length):
        r_bytes = list(os.urandom(length))
        limit = len(AttUtils.random_string_feed)
        r_string_list = list(map(lambda x: AttUtils.random_string_feed[x % limit], r_bytes))
        return ''.join(r_string_list)
