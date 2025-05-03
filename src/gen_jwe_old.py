# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jwe



key = {
          "kty": "RSA",
          "alg": "RSA1_5",
          "n": "w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vMZFMYv_V57174j411y-NQlZGb7iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGVfrPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYmjFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6rYaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0ye-gRVTtXDFEwABB--zwvlCw",
          "e": "AQAB",
          "kid": "rsa1_5",
          "d": "EjMvbuDeyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgixSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08on_QIF8afWUqCbsWWjEck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967NtOpxMPM5ro751KQ",
          "p": "-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7taDzh-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22umYjJS_kcopvf0",
          "q": "yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noGEU8O4MA9V3yhl91TFZy8unox0sGe0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8rF3jTLc8UWac",
          "dp": "Va9WWhPkzqY4TCo8x_OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZOPkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRfQ99DLnZfe_RElad2dV2mS1KMsfZHeffPtT0LaPJ_0erk",
          "dq": "M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgjCS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b13E0AGbpKsC3pYnaRvcGs",
          "qi": "8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9CO9W4K2gejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBPY8U449_iNgXd4"
       }

oaep_key = {
          "kty": "RSA",
          "alg": "RSA-OAEP-256",
          "n": "yVshpK_WdDeXJHEuoaQ9rYGW7uOcp87T-er4agcDkWe4SOJfRO0dEy1O-s9PVz4jPDLfndcOfpw3ooPB1dfSxaQCcltKAefAkRqSx4ExwPQUKMYll5XPzTmXbD8iLDJSR7Sz-1wTYS35oPSxFi-h4PwHtMNQLZ234KCepKhJ-in5d_Nx3f1mi9AmhMdDrkrWTpQvGiMkEkjT0th6SRnzVOzkzeEPHK6BQUT5HP2iV_lbvPrVdcBhXeCY31uwlsa2iHuJpFqvutuQDnt26nzT9jmJzr7tHtAoCt_Xs-hreld9rtDs05ukWPWI5sG4yfOvdKBkquryTb2_6ptAfWsyhw",
          "e": "AQAB",
          "kid": "rsa_oaep_256",
          "d": "Cg2KuHYu9s5vtVoRQfC5Q5hcuMCUaaxh2PBqRqDjBLdw8_KZXw-XjAWPE-aVx31KtQ61K2Q5TQjvniWF3-9Ojp-Jn7v_DelMK_JvsZY5rbCB8SczaUYJge2GKdldE2fPw9S5x6rpLMjm1aphzQHDyz_KArRdpGljbMuYIBBm4R5wlkZJ-AzfFKxyGAzrf13f4KacZD-uFWxdLd01yAxdw0wgG2oX6Rr36kT09Re-N_s5gnrDhi21MdYOuQNw1vOdHIkH37IvFkdT2g_5CNeW5GRdWcyuPbLCTbhFSrj4u8784VRSE_Zh6ycyXaYcyVXnBserCWGWD-r5I-z0lqHQQQ",
          "p": "-oHANaglt373EHf63OVKMPgbpznoSQXOou3xXlp-KWtMjsb1aPl13vai2ALjwSXacn1FTfxAS9lhRn_2pGW-Rx7QSlqmcOZ_2BBWmHAaeUL9iqzx69NFlIJowvI-sr24lJtUS53G2rKn77frCcuAItkNFvXc9DjYuodvH5v7QBU",
          "q": "zcV3cOrSvpPFJzlQ0XtIDzustpiOi8iv0PRdH0ax3fff6ceH3jhG80A8ypCoVGLUT3PzprJcxM9aWVSVuWIhx6fHscYZvTqBu6O2dyNVOxfAjfwWO_H0-2XWnFilEd5xKiWLYpiwpnpm1EQVFbAAWisDM1Yt9TN7yMJ18kg2cys",
          "dp": "DhrEIcFH7l79tjWrMEjQtpUhqXa_N21WRyIyludtdxONifR12OVC17z3SkZPYI6rEAsxncR4Mk0ZBwkpb_QylHqNq8IS4QR5akbxOUAGnZFCCU7XiDmrD0OQdnmBQjsga22bf25wxduNTRgD6ddFbbDe5c4OFMommcoKXbNAoEk",
          "dq": "x_gTyBdccLpYSXMI2FsPP0aF5PlC5hNE0TL44HEqX4UJBD7VCh70zGZr7YtBGqjknMYZTbFeOCEuM0vhKUR1gXrKtTfIQb3-36QMqaEbrg66IQGPdfgAVOO1-UCoQkJDBWtxFoM-gLrI_ZWgS_A7l2Tfel9Q0E6VCBf62VZWG_s",
          "qi": "hbKupLosNfXXH4RQ8iHazT3PCM83EyuGrvOALcH8m_DvEgOXRcIB0fFHWZe4SPJmEN381XvnQS_ki4Oj00KQCXfZXBfgyPoXpwym-g3z3m9_m7ymVUqk69wsk4Fc5y9RB0p-KIrBrTGsIMIrYVrn83u9fj_FiY9KeWB8tucS9lM"}


ct = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.sg6kjEU9vWfPwsAa7klB9Eh8fd1ouAKXR_wp3bsoP41MQa6jrq_dzd9rTZGu8MAtuAnoVE9OyM5W3cOCHdjlDOe1YSFO4WTedJBs_n8eKnT3KEZSKseZE4AltjtekKzO3B4EUMO3GPN-wyOyvJHoosFQQ7M-cxYVTZqNRk7XdKRy83i95YudXT0_AZBxCnqsYc6VzAtGUutqNp1fEfPnilGV-K-PqihYmEIicYq-DrKWp1EHscAijbaJyPFuVU2IsGG2P3s-Ov9N6VvykN4RySJAQCL3P1NK5QpNsgSra2pS_P18OerjlPR1FxSFVRKBIpPpvOKhMtjWqiN98S1Osg.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ"

ct_oaep = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.K_icyzruoFpk-HWas9Gvb3GRTk37leXNL8S3zRtisnQU41r7ZVu9E-ZQiJj4iG_6cAB7HLs1dJi8Iu6A6Ssg5ISOZSSDyOX9g8msYv-0fs8gMSDi2Ve7UucgYmXfInaox3ee_RyxmAlOKHHnDhmAw7aJSa2BMkD4SfH7wje3MMcI2Ah4iMYOc3wYHvelfqdGBfcH0OCrlQI51Y_r3PzW_jnmVBr7t406byDM9wz_yCAgBRmP71YJmW5OfXtdOvchArCBI-ZikhxLOljOub1-t5_QREiOjdWaPoitAQl8U14-j_O36gIeAQVz2iZPPeKm3ZwjlBJbHeFdaZyv4ZldMA.5pWpoi_FwYpTV-mZ.dFGb.ptkOsJEqDBRWB-3Vf47sDg"

c = "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"

mod = [
  ("orig", "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149ab3424395746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"),
  
  ("wrong type",
  "0001eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"),
  
  ("wrong key size",
  "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f515386003c3eb56ee98f084ba3b227875801be285f"),
  
  ("empty key", 
  "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c3eb56ee98f084ba3b227875801be285f00"),

  ("invalid padding", 
  "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c3eb56ee98f084ba3b227875801be285fff"),

  ("no zero", 
"0102eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"),

  ("too short",
  "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66c1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"),

  ("short padding",
  "0002eb00b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66c1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be285f"),
  
  ("modified message",
  "0002eb95b9bd2bad873923ff3cc6cecaca90412325cd2c34dbfca4b1541a6ab289d83eb5e5b8149454a1c815746582d93176c0269bcfcc216a52f49ea19c9974cb6b1b4be469cfdf0d3d6560398dac36d5795406e4761cdd926ddd61429fa1a5d73acdbfc4ec64b8f48ea1080452a0b80c0314486b9d4fbfc9bc774099577c8ed0774df15fffcb83df2c0b30294fe2755fa8c0838b6a313817369f862bad136c8ddd10a1708315b84ecaefd6dc4d1e4b2d441412447947cde0d0a4a57e3df014defcc3a763c0eec33eb787ff8f558aca7bd8d33d033b4494bfbf66cb88e552e1c2d9422a68311e7607f14f5153863c003eb56ee98f084ba3b227875801be2821"),
] 


def test(key, ct):
  print("===== test =====")
  n = jwe.b64toint(key['n'])
  p = jwe.b64toint(key['p'])
  q = jwe.b64toint(key['q'])
  assert n == p*q
  e = jwe.b64toint(key['e'])
  d = jwe.b64toint(key['d'])
  parts = [jwe.dec(x) for x in ct.split(".")]
  for p in parts:
    print(len(p), p)
  c = int.from_bytes(parts[1], 'big')
  print(c)
  m = pow(c, d, n)
  assert pow(m, e, n) == c
  print(m.to_bytes(256, 'big').hex())
  for cmt, mh in mod:
    m0 = int(mh, 16)
    c0 = pow(m0, e, n)
    p0 = parts[:]
    p0[1] = c0.to_bytes(256, "big")
    print("comment:", cmt)
    tt = [jwe.enc(p) for p in p0]
    print(".".join(tt))

def decode_pkcs15(m, n):
  bl = (n.bit_length() + 7) // 8
  bt = m.to_bytes(bl, "big")
  if bt[0] != 0: return None
  if bt[1] != 2: return None
  for i in range(2, bl):
    if bt[i] == 0:
      if i >= 10:
        return bt[i+1:]
  return None
    
def test_oaep(key, ct, alg):
  print("===== test_oaep =====")
  n = jwe.b64toint(key['n'])
  p = jwe.b64toint(key['p'])
  q = jwe.b64toint(key['q'])
  assert n == p*q
  e = jwe.b64toint(key['e'])
  d = jwe.b64toint(key['d'])
  parts = [jwe.dec(x) for x in ct.split(".")]
  for p in parts:
    print(len(p), p)
  c = int.from_bytes(parts[1], 'big')
  print(c)
  m = pow(c, d, n)
  assert pow(m, e, n) == c
  M = {2}
  for i in range(1, 200000):
    mi = m * i % n
    d = decode_pkcs15(mi, n)
    if d is None:
      continue
    print(i, len(d))
    M.add(i)
  for i in range(1, 40000000):
    mi = m * i % n
    d = decode_pkcs15(mi, n)
    if d is None:
      continue
    if len(d) in [0, 8, 16, 24, 32]:
      print(i, len(d))
      M.add(i)
  print(M)
  header = '{' + f'"alg":"RSA1_5","enc":"{alg}"' + '}'
  print("original header:", parts[0])
  print("modified header:", header)
  for i in sorted(M):
    ci = c * pow(i, e, n) % n
    mod = parts[:]
    mod[0] = bytes(header,"ascii")
    mod[1] = ci.to_bytes(256, "big")
    print("comment:", i)
    tt = [jwe.enc(p) for p in mod]
    print(mod)
    print(".".join(tt))


if __name__ == "__main__":
  test(key, ct)
  test_oaep(oaep_key, ct_oaep, "A128GCM")

