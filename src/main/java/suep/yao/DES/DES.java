package suep.yao.DES;

import java.util.ArrayList;
import java.util.List;

public class DES {


    //初始置换表
    final static char[] IP_TABLE = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    //逆初始置换表
    final static char[] IP1_TABLE = {

            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
    //扩展置换表
    final static char[] EXTENSION_TABLE = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};


    //P盒置换表
    final static char[] P_TABLE = {

            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
    //密钥PC-1置换表
    final static char[] PC1_TABLE = {

            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

    //密钥PC-2置换表
    final static char[] PC2_TABLE = {

            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
    //循环左移表
    final static char[] LOOP_TABLE = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    //S盒
    final static char[][][] S_BOX = {{//S盒1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},}, {//S盒2
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

    }, {//S盒3
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

    }, {//S盒4
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

    }, {//S盒5
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

    }, {//S盒6
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

    }, {//S盒7
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

    }, {//S盒8
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},

    }};

    /**
     * 初始置换IP
     *
     * @param ip 输入的64位明文
     * @return 按照IP_TABLE重新排序后的表 inverse
     */
    private static char[] ipTransform(char[] ip) {
        char[] chars = new char[64];
        for (int i = 0; i < 64; i++) {
            chars[i] = ip[IP_TABLE[i] - 1];
        }
        return chars;
    }

    /**
     * ip逆置换
     *
     * @param ip
     * @return
     */
    private static char[] ipInverseTransform(char[] ip) {
        char[] chars = new char[64];
        for (int i = 0; i < 64; i++) {
            chars[i] = ip[IP1_TABLE[i] - 1];
        }
        return chars;
    }

    /**
     * 将输入的明文和密钥转化成64的倍数的字符数组
     *
     * @param plaintext
     * @return
     */
    public static List<char[]> StringToArrayChar(String plaintext) {
        ArrayList<char[]> characters = new ArrayList<>();
        //将明文转换成字符数组
        byte[] bytes = plaintext.getBytes();

        int length = bytes.length / 8;
        for (int i = 0; i < length; i++) {
            StringBuffer stringBuffer = new StringBuffer();
            for (int j = 0; j < 8; j++) {
                int b = bytes[i * 8 + j];
                b |= 256;
                String s = Integer.toBinaryString(b);
                s = s.substring(s.length() - 8);
                stringBuffer.append(s);
            }
            char[] chars = stringBuffer.toString().toCharArray();
            characters.add(chars);
        }

        byte[] bytes1 = new byte[8];
        if (bytes.length % 8 != 0) {
            int i1 = length * 8;
            int i2 = bytes.length - i1;
            for (int i3 = 0; i3 < bytes1.length; i3++) {
                if (i3 < i2) {
                    bytes1[i3] = bytes[i1 + i3];
                } else {
                    bytes1[i3] = 0;
                }
            }
            bytes1[7] = (byte) (7 - i2);
        } else {
            bytes1 = new byte[]{0, 0, 0, 0, 0, 0, 0, 7};
        }
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            int b = bytes1[i];
            b |= 256;
            String s = Integer.toBinaryString(b);
            stringBuffer.append(s.substring(s.length() - 8));
        }

        characters.add(stringBuffer.toString().toCharArray());
        return characters;
    }

    /**
     * 解密
     *
     * @param ciphertext
     * @param key
     * @return
     */
    public String Decrypt(String ciphertext, String key) {
        char[] charKey = this.getCharKey(key);
        char[] charsCiphertext = ciphertext.toCharArray();
        int length = charsCiphertext.length / 64;
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < length; i++) {
            char[] chars = new char[64];
            for (int j = 0; j < 64; j++) {
                chars[j] = charsCiphertext[i * 64 + j];
            }
            char[] des = this.DES(chars, charKey, false);
            stringBuffer.append(new String(des));
        }
        return this.decode(stringBuffer.toString());
    }

    /**
     * 解码成字符串
     *
     * @param text 10101010111101010101000000000011111101010
     * @return
     */
    public String decode(String text) {
        String substring = text.substring(text.length() - 8);
        byte subByte = Byte.parseByte(substring, 2);
        String str = text.substring(0, text.length() - 8 - subByte * 8);
        int length = str.length() / 8;
        byte[] bytes = new byte[length];

        for (int i = 0; i < length; i++) {
            String s = str.substring(i * 8, i * 8 + 8);
            bytes[i] = Byte.parseByte(s, 2);
        }
        String s = new String(bytes);
        return s;
    }

    /**
     * 获取密文
     *
     * @param plaintext
     * @param key
     * @return
     */
    public String getCiphertext(String plaintext, String key) {
        StringBuffer ciphertext = new StringBuffer();
        List<char[]> plaintextArrayChar = StringToArrayChar(plaintext);
//        List<char[]> keyArrayChar = StringToArrayChar(key);
        char[] charKey = this.getCharKey(key);
        for (char[] chars : plaintextArrayChar) {
            char[] des = this.DES(chars, charKey, true);
            ciphertext.append(new String(des));
        }
        return ciphertext.toString();

      /*
        int plaintextSize = plaintextArrayChar.size();
        int keySize = keyArrayChar.size();
        if (plaintextSize > keySize) {
            for (int i = 0; i < plaintextSize; i++) {
                char[] plaintextChar = plaintextArrayChar.get(i);
                char[] keyChar;
                if (i < keySize) {
                    keyChar = keyArrayChar.get(i);
                } else {
                    keyChar = keyArrayChar.get(keySize - 1);
                }
                char[] chars = this.DES(plaintextChar, keyChar, true);
                ciphertext.append(new String(chars));
            }
        } else {
            for (int i = 0; i < keySize; i++) {
                char[] plaintextChar;
                if (i < plaintextSize) {
                    plaintextChar = plaintextArrayChar.get(i);
                } else {
                    plaintextChar = plaintextArrayChar.get(plaintextSize - 1);
                }
                char[] keyChar = keyArrayChar.get(i);
                char[] chars = this.DES(plaintextChar, keyChar, true);
                ciphertext.append(new String(chars));
            }
        }
        return ciphertext.toString();*/
    }

    /**
     * 将输入的密钥转化成64的字符数组
     *
     * @param key
     * @return
     */
    public char[] getCharKey(String key) {
        byte[] keyBytes = key.getBytes();
        int keyLength = keyBytes.length;
        if (keyLength < 8) {
            byte[] keyBytes1 = new byte[8];
            for (int i = 0; i < 8; i++) {
                if (i < keyLength) {

                    keyBytes1[i] = keyBytes[i];
                } else {
                    keyBytes1[i] = 0;
                }
            }
            keyBytes = keyBytes1;
        }
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int b = keyBytes[i];
            b |= 256;
            String s = Integer.toBinaryString(b);
            stringBuffer.append(s.substring(s.length() - 8));

        }
        return stringBuffer.toString().toCharArray();

    }

    /**
     * DES加密
     *
     * @param plaintext 明文
     * @param key       密钥
     * @return
     */

    private char[] DES(char[] plaintext, char[] key, boolean isEncrypt) {
        //ip初始置换
        plaintext = ipTransform(plaintext);

        //分为左右两部分
        char[] left = new char[32];
        char[] right = new char[32];
        for (int i = 0; i < 32; i++) {
            left[i] = plaintext[i];
            right[i] = plaintext[i + 32];
        }

        char[] key_i = new char[56];
        //密钥置换1
        for (int j = 0; j < 56; j++) {
            key_i[j] = key[PC1_TABLE[j] - 1];
        }
        //获取16轮的子密钥
        ArrayList<char[]> keys = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            keys.add(this.getKey(key_i, i));
        }
        //16轮迭代
        for (int i = 0; i < 15; i++) {
            //获取子密钥
            if (isEncrypt) {
                //加密
                key = keys.get(i);
            } else {
                //解密
                key = keys.get(15 - i);
            }
            char[] left_i = left;
            left = right;
            right = this.Xor(left_i, F(right, key));
        }
        if (isEncrypt) {
            left = this.Xor(left, F(right, keys.get(15)));
        } else {
            left = this.Xor(left, F(right, keys.get(0)));
        }
        //将左右两部分合并
        char[] ciphertext = new char[64];
        for (int i = 0; i < 32; i++) {
            ciphertext[i] = left[i];
            ciphertext[i + 32] = right[i];
        }
        //ip逆置换
        ciphertext = ipInverseTransform(ciphertext);
        return ciphertext;
    }

    /**
     * 异或运算
     */
    private char[] Xor(char[] a, char[] b) {
        char[] result = new char[a.length];
        int temp;
        if (a.length != b.length) {
            System.err.println("异或运算左右两边长度不同！请检查Xor函数及其调用的参数");
            return null;
        }
        for (int i = 0; i < a.length; i++) {
            temp = ((int) a[i]) ^ ((int) b[i]);
            result[i] = (temp + "").toCharArray()[0];
        }
        return result;
    }

    /**
     * 获取子密钥
     *
     * @param key 密钥
     * @param i   轮数
     * @return
     */
    private char[] getKey(char[] key, int i) {
        //PC-1置换
        char[] chars = key;
        //分为左右两部分
        char[] left = new char[28];
        char[] right = new char[28];
        for (int j = 0; j < 28; j++) {
            left[j] = chars[j];
            right[j] = chars[j + 28];
        }
        //左右两部分分别循环左移
        int loop = LOOP_TABLE[i]; //循环左移的次数
        //存储左移的前部分
        ArrayList<Character> left_loop = new ArrayList<Character>();
        ArrayList<Character> right_loop = new ArrayList<Character>();
        for (int i1 = 0; i1 < loop; i1++) {
            left_loop.add(left[i1]);
            right_loop.add(right[i1]);
        }
        //左移
        for (int i1 = 0; i1 < left.length - loop; i1++) {
            left[i1] = left[i1 + loop];
            right[i1] = right[i1 + loop];
        }
        //将左移的前部分放回
        int index = 0;
        for (int i1 = left.length - loop; i1 < left.length; i1++) {
            left[i1] = left_loop.get(index);
            right[i1] = right_loop.get(index);
            index++;
        }
        //合并
        for (int j = 0; j < 28; j++) {
            chars[j] = left[j];
            chars[j + 28] = right[j];
        }
        //PC-2置换
        char[] key_ = new char[48];
        for (int j = 0; j < 48; j++) {
            key_[j] = chars[PC2_TABLE[j] - 1];
        }
        return key_;
    }

    /**
     * F轮函数
     *
     * @param R
     * @param key
     * @return
     */
    private static char[] F(char[] R, char[] key) {
        //F函数
        //1.1E扩展
        char[] E = new char[48];
        int Ri = 0, temp = 1;
        for (int i = 1; i < 48; i++) {
            E[i] = R[Ri];
            if (temp % 4 == 0) {
                i = i + 2;
            }
            temp++;
            Ri++;
        }
        for (int i = 5; i < 42; i = i + 6) {
            E[i] = E[i + 2];
            E[i + 1] = E[i - 1];
        }
        E[0] = E[46];
        E[47] = E[1];
        //1.2置换
        for (int i = 0; i < E.length; i++) {
            E[i] = E[EXTENSION_TABLE[i] - 1];
        }
        //2.1 异或

        for (int i = 0; i < 48; i++) {

            int i1 = E[i] ^ key[i];


            E[i] = (i1 + "").toCharArray()[0];
        }
        //3.1 S盒压缩
        char[] S;
        char[] S_int = new char[32];
        int row = 0, col = 0;
        for (int i = 0; i < 8; i++) {
            row = Integer.parseInt(String.valueOf(E[i * 6]) + String.valueOf(E[i * 6 + 5]), 2);
            col = Integer.parseInt(String.valueOf(E[i * 6 + 1]) + String.valueOf(E[i * 6 + 2]) + String.valueOf(E[i * 6 + 3]) + String.valueOf(E[i * 6 + 4]), 2);
            S_int[i] = S_BOX[i][row][col];
        }
        //3.2 转化为二进制数
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < S_int.length; i++) {
            S_int[i] |= 16;
            String binaryString = Integer.toBinaryString(S_int[i]);
            String substring = binaryString.substring(binaryString.length() - 4);
            sb.append(substring);
        }
        S = sb.toString().toCharArray();
        //4.1 P置换
        char[] P = new char[32];
        for (int i = 0; i < 32; i++) {
            P[i] = S[P_TABLE[i] - 1];
        }
        return P;
    }

}
