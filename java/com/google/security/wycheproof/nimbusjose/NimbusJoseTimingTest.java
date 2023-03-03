/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof.nimbusjose;

import static org.junit.Assert.fail;

import com.google.security.wycheproof.TestUtil;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWK;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test measures timing differences during decryption of RSA PKCS #1 encrypted ciphertexts.
 *
 * <p>Some of the ciphertexts have valid PKCS #1 padding, while other messages have invalid
 * paddings. The test shows that at least one older version has sufficiently large timing
 * differences, so that ciphertexts with valid paddings can be reliably distinguished from
 * ciphertexts with invalid paddings.
 *
 * <p>The timing difference is caused by the exception handling. Exception handling is rather slow
 * in Java. It adds somewhere 1-2 microseconds to the runtime. This timing difference is detectable
 * during a unit test. OpenJdk reduces the timing difference of RSA PKCS #1 v1.5 decryption, by
 * always constructing an exception even if that exception is not being thrown. Nimbus-Jose does not
 * implement such a counter measurement.
 */
@RunWith(JUnit4.class)
public class NimbusJoseTimingTest {

  private String rsaKey =
      "{"
          + "\"kty\": \"RSA\","
          + "\"use\": \"enc\","
          + "\"alg\": \"RSA1_5\","
          + "\"n\": \"w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vM"
          + "ZFMYv_V57174j411y-NQlZGb7iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGV"
          + "frPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYmjFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6r"
          + "YaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0ye-gRVTtX"
          + "DFEwABB--zwvlCw\","
          + "\"e\": \"AQAB\","
          + "\"kid\": \"rsa1_5\","
          + "\"d\": \"EjMvbuDeyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgi"
          + "xSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB"
          + "8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08on_QIF8afWUqCbsWWjE"
          + "ck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967N"
          + "tOpxMPM5ro751KQ\","
          + "\"p\": \"-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7t"
          + "aDzh-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22um"
          + "YjJS_kcopvf0\","
          + "\"q\": \"yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noG"
          + "EU8O4MA9V3yhl91TFZy8unox0sGe0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8"
          + "rF3jTLc8UWac\","
          + "\"dp\": \"Va9WWhPkzqY4TCo8x_OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZO"
          + "PkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRfQ99DLnZfe_RElad2dV2mS1KMsfZHeff"
          + "PtT0LaPJ_0erk\","
          + "\"dq\": \"M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgjCS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7"
          + "TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b13E0AGbp"
          + "KsC3pYnaRvcGs\","
          + "\"qi\": \"8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9CO9W4K2g"
          + "ejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBP"
          + "Y8U449_iNgXd4\""
          + "}";

  private String[] jwe = {
    // The GCM tag has been modified: Not internal exception is thrown.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.sg6kjEU9vWfPwsAa7klB9Eh8fd1ouAKXR_wp3bsoP41M"
        + "Qa6jrq_dzd9rTZGu8MAtuAnoVE9OyM5W3cOCHdjlDOe1YSFO4WTedJBs_n8eKnT3KEZSKseZE4AltjtekKzO"
        + "3B4EUMO3GPN-wyOyvJHoosFQQ7M-cxYVTZqNRk7XdKRy83i95YudXT0_AZBxCnqsYc6VzAtGUutqNp1fEfPn"
        + "ilGV-K-PqihYmEIicYq-DrKWp1EHscAijbaJyPFuVU2IsGG2P3s-Ov9N6VvykN4RySJAQCL3P1NK5QpNsgSr"
        + "a2pS_P18OerjlPR1FxSFVRKBIpPpvOKhMtjWqiN98S1Osg.46AsIpPgnJCLH0Xm.u2rG.KyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The padding type is invalid.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.klW2vZxZ57Prp1pSmfArR1ZtALMQM4N5_lLM8v2OhO8K"
        + "ukJVNR9h548e6ZNNQhmXYa9e4vEb79BKjHeck1FsGtl0l2mSs4byhOXkMXVMRpmUZolwEXE-cwfHvvn6K-nW"
        + "Wh6BDJI_ErZ7I_9YOGpu6jUpYqKB4l2nobg2CopJ58uOJtulvrW11WerBLfxMQ9CCinMdUi2hL7x1avSU4AP"
        + "LSk2CC6PUlciDyuLeFxL59fCct5zOZ-W3uWjCC7pm9nDaIlLei2fYdTxOkAYY42VDV454q9OgrpH7pynxlmu"
        + "AEvbWl0XriPXGgQmrMaTyXUpXBKwdwdHFzx88XL6r1refA.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // Message size is wrong: No internal exceptions thrown.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.oyVTmkyoChxFtyCtiKhv8OpBJcV6C6s_gMFSSRJBNStp"
        + "dHPzq2YmroTfXGj1J1plFG4BBQwIZtdt6rIS6YkCvTLGqP1hds9CAO1a_bgRyoAVuOVvH2vmz5U2r74_SRbA"
        + "zD35M7yZ_tSnnEdMFlHMFbf5uNwmgArrtPgh0V5OLn5i4XIc154FLTiQlvAEhUxiPuYBkm_1GBiYEH4JjP2R"
        + "KXAUx_TxAVwPsOfIPAVrO0Ev_nvdtVLCE-uOn8WQbxh4wwOztaXOV1HIaPrl7HN-YtDOA840QUHm97ZZLAPR"
        + "gLzGlkMI0ZS8QkYdb9_FT3KMbNu60nBKEniv2uhBdIhM9g.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The message is empty: No internal exceptions thrown.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.PPGY-3DqgauQaPWTcjCkmjVG7-m8Z803f2TPeVoDYQmV"
        + "KLiONBOVOigTKvP_6LBnVZ41TYwqcjbHxsrz5VS9r_tYHV_6njBX2EHIdsAYoZngN7ROAF2GTCKV8T5F0V0j"
        + "GUejE5g3RBg7-_8qz-WljVf86sqnSiUtnXBORwWmiyvAgWqjYDDWxgzmdNNjLGn2zbJoJJpZvfSjKZwL4PCC"
        + "AEXSW6s-dcdsXtUn3ZHNL2Bk8IWIcJQ1MjuBSJ1BtNO0n-0WkQuwXDD2KnwAisaC3-pTjTII8z1lep1XeOma"
        + "UYacqkYhP0UB5LduX5rAITsJ2z7b5ZGIjGEuI4G-G_tD5g.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The padding is invalid.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ksmeZ6dBbP0UfDEaLXlqPl2XDaAA29kGlKtDb89x-4xN"
        + "5-A6bx2umI_ToHK2GadzxUOgKROCACYb6rmKsqsQCOZaBsnq_4mDII1W0pja7Lz4zTnr7R3O4kALg4zXqG-g"
        + "SlcDA7k1NgkpMDS15PjMmADqyqxbxQsXdfjstN324iqdvYGh6NsckkfTSWxDVAqiSR9fW8PsIbo3uSMokNaC"
        + "-f64CDWIB9AsCxhF-3mnFbxXNxw7JE0upOgG4enQ8kZkwi_v54HBqAau1YNW7gPhFV8ElTQ71J6aHB3dja23"
        + "lbWdaJmrK6PJE7gEeZmUbFkSYmuyzRUS-NGfXA23fYv5JQ.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The first byte is not zero.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.sCdKUt2AR2G6h_qfQ3ORIcv4ffcHsqzGQSFqoGvCAIJb"
        + "Ho1m-UjkybVsIb73r1iwbrR09Y-94l4Tuo-6BO8tKgea0KUj4TPPs5Q7TkjtpTKg5qobO74aK3zY_YqB1yR6"
        + "ZFwTPSv8He7qd9594iY_F3kjiEycsp3NPXcdcq9nhoffpQ4YUKwkTLYY7imIxYTe3ouU5Z2lskM85UBnwV5y"
        + "zFduM1DiHx5bLUqA6alEqcGrGadxc0vA3J5e2_ylsyiw_omjqeNV3xdY8JB9E9gjA6xcNy92kagaDi5wDWrY"
        + "IAmLYkeIZwUBO3eTftV_UwOrLskPE4eToo-EbVegSwZUZA.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // paddedMessageTooShort
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.wlsnZTya4NEzU7CGEBMWzxz6qByjyjkbiaOiDMcpDUNo"
        + "z_eJvxgHwGMI1gfEUaR1u6fOijZlGkJsso8VPTvL5wlqINBAaxm6vYJK3bGbyS9YQ6rvddLvMTAxzxASBG2q"
        + "IFlsLRKkHZeV2ZIUZB8QJyfwYIfHyjuaVX-PL3s0heRNm5H3FmUg87_fXj40XmmKuMH3MqZvoeskd4h-f1lA"
        + "ztS3oiKTSF7yh43t3RXz-vRY6OTprWyfOVdYau3jdt0AVK_2QNFN3xNdhc3X4BGVyaNckGIyPNCEcD0E8zz3"
        + "mbFn8MBIE8uNtHJspXv1wlB_b5t9P0FAzrQ0d-INcr-Kbw.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The padding is too short
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ldK3WAsbjKZhRsFTWbvtr6aaah-Xz17QJOWUFUcldsb0"
        + "eEcgAEphF2OO6FJDPGjxlNSXedfonFbtZDLxTxleK8k3w2GNEKNGJUqFbvG1siUoE1lq5piqQ8X9XH2hZOeU"
        + "aJHGgp51nu0AuG3PenvD84qEZeGlbIv7_Mwp0jdybHia8C_BkX1B_bZjmpIafLr9jmRYnK0JAoAfUujPNhY0"
        + "DXzFJIQT13PaZ8wzPLaK78X4eQSCV5Y97CA6blTHlxlZV2pw0y7BxAaqq4uCTeqzfheGWS9cq21XBYRzpa-l"
        + "iZ3tKv5AjSIZmZ825hvypzBx-D1bmx9Ip0eLPKkmaon-hQ.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ",
    // The message has been modified: No internal exceptions are thrown.
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ewR6Fg0UJYVcHKgIC9x-mD8q5bXFBE7VTsdTaSWSFcOP"
        + "SI14VlMFDxXALR7kUfP2VA5qtxxlONGNeNvpr2v8C--Z1KfIWC_gvPSZMrGYrKJM1hauhjQb5jAQfz2NuuIg"
        + "3HG8b5YAG8pdhur7UwdNRTb10vt33FFYfMYLutulyrOq5l_ak4cDtaDDk8K0_isPMa6r6aQKqXEFTwTKNGlq"
        + "3qwrv9-5o0JrVzEGIKIkvsKmOk6m2g2QoBn-66_gcLkw3pPn5lWHyt8JI-rydCSTjFN2jSYiePMn6gBInizZ"
        + "my8MU_hq0tRwlbi2_J-xx-GbYXHTkuYlDIUqr0DY1onWFg.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEE"
        + "HiaqhiQ"
  };

  /**
   * Timing test for RSA1_5 implemented in Nimbus-Jose.
   *
   * <p>The test generates some simple statistics about the time it takes to decrypt a number of
   * RSA1_5 encrypted messages in Nimbus-Jose. A sample output of the test is
   *
   * <pre>
   * j=0 cnt=2608 20%=1085621
   * j=1 cnt=1546 20%=1087211
   * j=2 cnt=2541 20%=1085753
   * j=3 cnt=2642 20%=1085552
   * j=4 cnt=1539 20%=1087220
   * j=5 cnt=1568 20%=1087186
   * j=6 cnt=1517 20%=1087242
   * j=7 cnt=1552 20%=1087204
   * j=8 cnt=2482 20%=1085789
   * </pre>
   *
   * <p>jwe[0], jwe[2], jwe[3] and jwe[8] are messages containing valid PKCS #1 paddings. For these
   * messages the RSA decryption succeeds. The other messages contains an invalid PKCS #1 padding.
   * While decrypting the messages an exception is thrown. Nimbus-Jose does catch these exceptions,
   * and uses a random GCM key in these cases. In every case eventually the same exception is
   * thrown: com.nimbusds.jose.JOSEException: AES/GCM/NoPadding decryption failed: Tag mismatch!
   * However, throwing and catching the exceptions from invalid PKCS #1 paddings add somewhere in
   * the order of 1500 ns to the runtime. This timing difference is observable, but requires
   * repetitions on noisy systems. Hence, an attack is possible, but its complexity is at the moment
   * not known.
   *
   * <p>The version tested (version 9.2) is also susceptible to chosen ciphertext attacks if the key
   * is an RSA_OAEP key. This can be tested by changing the algorithm in rsaKey above. This attack
   * works since Nimbus-Jose does not check if the algorithm in the key and the algorithm in the JWE
   * header match.
   */
  @Test
  public void testRsaTiming() throws Exception {
    // Timings can be quite noisy.
    // At the moment it is unclear what a good method is to
    // distinguish distributions. One method that seems to be somewhat
    // reliable is to look at the 20% of the fastest timings.
    //
    // The test uses a threshold that is the maximal time of the fastest 20% of the measurements.
    // Each decryption is repeated 10000 times. If all inputs have the same timing distribution
    // then we would expect to see about 2000 measurements per input that are faster than the
    // threshold. The probabilify of seeing less than 1750 or more than 2250 measurments smaller
    // than threshold without timing differences is smaller than 2^-32. Hence such an event fails
    // the test.
    int runs = 10000;
    int minBound = 1750;
    int maxBound = 2250;

    // The number of decryptions done before starting to measure.
    int warmup = 100;
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      TestUtil.skipTest("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    JWK key = JWK.parse(rsaKey);
    JWEDecrypter decrypter = new RSADecrypter(key.toRSAKey());
    JWEObject[] parsedJwe = new JWEObject[jwe.length];
    for (int i = 0; i < jwe.length; i++) {
      parsedJwe[i] = JWEObject.parse(jwe[i]);
    }

    // Warmup
    for (int i = 0; i < warmup; i++) {
      for (int j = 0; j < jwe.length; j++) {
        try {
          parsedJwe[j].decrypt(decrypter);
          if (i == 0) {
            System.out.println("j=" + j + " decrypted");
          }
        } catch (Exception ex) {
          // Prints the exception the first time a ciphertext is decrypted.
          // It is important that this exception is the same for each ciphertext.
          // This test passes.
          if (i == 0) {
            System.out.println("j=" + j + ":" + ex);
          }
        }
      }
    }

    long[][] timing = new long[jwe.length][runs];
    long[] allTiming = new long[jwe.length * runs];
    for (int i = 0; i < runs; i++) {
      for (int j = 0; j < jwe.length; j++) {
        long start = bean.getCurrentThreadCpuTime();
        try {
          parsedJwe[j].decrypt(decrypter);
        } catch (Exception ex) {
          // We are only interested in the timing
        }
        long time = bean.getCurrentThreadCpuTime() - start;
        timing[j][i] = time;
        allTiming[j + i * jwe.length] = time;
      }
    }

    boolean passed = true;
    Arrays.sort(allTiming);
    // threshold is an upper bound on the 20% fastest decryptions.
    long threshold = allTiming[allTiming.length / 5];

    for (int j = 0; j < jwe.length; j++) {
      Arrays.sort(timing[j]);
      int cnt = 0;
      for (int i = 0; i < runs; i++) {
        if (timing[j][i] < threshold) {
          cnt += 1;
        }
      }
      if (cnt <= minBound || cnt >= maxBound) {
        passed = false;
      }
      System.out.println("j=" + j + " cnt=" + cnt + " 20%=" + timing[j][runs / 5]);
    }
    if (!passed) {
      fail("Significant timing differences detected.");
    }
  }
}
