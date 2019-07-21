import PyKCS11


def sign_message(text):
	"""
	Function that allows user to sign messages.

	Returns
	-----
	signed_message - Signed message signed by private key
	"""
	lib = '/usr/local/lib/libpteidpkcs11.so'
	pkcs11 = PyKCS11.PyKCS11Lib()
	pkcs11.load(lib)
	slots = pkcs11.getSlotList()
	for slot in slots:
		session = pkcs11.openSession(slot)
		private_key = session.findObjects([
				(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
				(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
				])[0]
		mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
		signed_message = bytes(session.sign(private_key, text, mechanism))
		session.closeSession
	return signed_message 
