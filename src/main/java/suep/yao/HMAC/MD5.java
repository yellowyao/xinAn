package suep.yao.HMAC;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Random;

/************************************************* 
 md5 类实现了RSA Data Security, Inc.在提交给IETF
 的RFC1321中的MD5 message-finalResult 算法。
 *************************************************/


class Variable {
    long[] state = new long[4];
    long[] count = new long[2];
    byte[] buffer = new byte[64];

    public Variable() {
        this.reset();
    }

    public void reset() {
        this.count[0] = 0L;
        this.count[1] = 0L;
        this.state[0] = 0x67452301L;
        this.state[1] = 0xefcdab89L;
        this.state[2] = 0x98badcfeL;
        this.state[3] = 0x10325476L;
    }
}


public class MD5 {
    private Variable variable = new Variable();

    static final int S[][] = {{7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};
    static final byte[] OFFEST = new byte[64];

    public byte[] MD5Bytes(byte[] in) {
        this.variable.reset();
        this.md5Update(in, in.length);
        byte[] finalResult = this.md5Final();
        return finalResult;
    }


    public String MD52Str(String in) {
        //md5Init();
        byte[] finalResult = this.MD5Bytes(in.getBytes());
        String finalHex2Str = "";
        for (int i = 0; i < 16; i++) {
            finalHex2Str += this.b2Hex(finalResult[i]);
        }
        return finalHex2Str;
    }

    public MD5() {
        for (int i = 0; i < 64; i++) {
            OFFEST[i] = 0;
        }
        OFFEST[0] = -128;
    }


    /*
     * F, G, H ,I 是4个基本的MD5函数
     */

    long F(long temp, long y, long z) {
        return (temp & y) | ((~temp) & z);
    }

    long G(long temp, long y, long z) {
        return (temp & z) | (y & (~z));
    }

    long H(long temp, long y, long z) {
        return temp ^ y ^ z;
    }

    long I(long temp, long y, long z) {
        return y ^ (temp | (~z));
    }  
     
    /* 
      FF,GG,HH和II将调用F,G,H,I进行近一步变换 
    */


    private long FF(long A, long B, long C, long D, long temp, long s, long ac) {
        A += this.F(B, C, D) + temp + ac;
        A = ((int) A << s) | ((int) A >>> (32 - s));
        A += B;
        return A;
    }


    private long GG(long A, long B, long C, long D, long temp, long s, long ac) {
        A += this.G(B, C, D) + temp + ac;
        A = ((int) A << s) | ((int) A >>> (32 - s));
        A += B;
        return A;
    }

    private long HH(long A, long B, long C, long D, long temp, long s, long ac) {
        A += this.H(B, C, D) + temp + ac;
        A = ((int) A << s) | ((int) A >>> (32 - s));
        A += B;
        return A;
    }

    private long II(long A, long B, long C, long D, long temp, long s, long ac) {
        A += this.I(B, C, D) + temp + ac;
        A = ((int) A << s) | ((int) A >>> (32 - s));
        A += B;
        return A;
    }

    /* 
      md5Update是MD5的主计算过程，inbuf是要变换的字节串，inputlen是长
    */
    private void md5Update(byte[] in, int len) {

        byte[] block = new byte[64];
        int index = (int) (this.variable.count[0] >>> 3) & 0x3F;
        // /* Update number of bits */
        if ((this.variable.count[0] += (len << 3)) < (len << 3))
            this.variable.count[1]++;

        this.variable.count[1] += (len >>> 29);
        int tempLen = 64 - index;
        int i = tempLen;

        // Transform as many times as possible.
        if (len >= tempLen) {
            this.md5Memcpy(this.variable.buffer, in, index, 0, tempLen);
            this.md5Transform(this.variable.buffer);
            for (i = tempLen; i + 63 < len; i += 64) {
                this.md5Memcpy(block, in, 0, i, 64);
                this.md5Transform(block);
            }
            index = 0;
        } else {
            i = 0;
        }
        this.md5Memcpy(this.variable.buffer, in, index, i, len - i);
    }

    /* 
      md5Final整理和填写输出结果 
    */
    private byte[] md5Final() {
        byte[] bits = new byte[8];
        int index, offestNum;
        ///* Save number of bits */
        this.Encode(bits, this.variable.count, 8);

        ///* Pad out to 56 mod 64.
        index = (int) (this.variable.count[0] >>> 3) & 0x3f;
        offestNum = (index < 56) ? (56 - index) : (120 - index);
        this.md5Update(OFFEST, offestNum);

        ///* Append length (before OFFEST) */
        this.md5Update(bits, 8);
        ///* Store state in finalResult */

        byte[] finalResult = new byte[16];
        this.Encode(finalResult, this.variable.state, 16);
        return finalResult;
    }  
       
    /* md5Memcpy是一个内部使用的byte数组的块拷贝函数，从input的inpos开始把len长度的 
　　　　　 字节拷贝到output的outpos位置开始 
    */

    private void md5Memcpy(byte[] output, byte[] input, int outpos, int inpos, int len) {
        for (int i = 0; i < len; i++) {
            output[outpos + i] = input[inpos + i];
        }
    }

    /* 
      md5Transform是MD5核心变换程序，有md5Update调用，block是分块的原始字节 
    */
    private void md5Transform(byte block[]) {
        long A = this.variable.state[0], B = this.variable.state[1], C = this.variable.state[2], D = this.variable.state[3];
        long[] temp = new long[16];


        this.Decode(temp, block, 64);


        /* Round 1 S[][]*/
        A = this.FF(A, B, C, D, temp[0], S[0][0], 0xd76aa478L);
        D = this.FF(D, A, B, C, temp[1], S[0][1], 0xe8c7b756L);
        C = this.FF(C, D, A, B, temp[2], S[0][2], 0x242070dbL);
        B = this.FF(B, C, D, A, temp[3], S[0][3], 0xc1bdceeeL);
        A = this.FF(A, B, C, D, temp[4], S[0][0], 0xf57c0fafL);
        D = this.FF(D, A, B, C, temp[5], S[0][1], 0x4787c62aL);
        C = this.FF(C, D, A, B, temp[6], S[0][2], 0xa8304613L);
        B = this.FF(B, C, D, A, temp[7], S[0][3], 0xfd469501L);
        A = this.FF(A, B, C, D, temp[8], S[0][0], 0x698098d8L);
        D = this.FF(D, A, B, C, temp[9], S[0][1], 0x8b44f7afL);
        C = this.FF(C, D, A, B, temp[10], S[0][2], 0xffff5bb1L);
        B = this.FF(B, C, D, A, temp[11], S[0][3], 0x895cd7beL);
        A = this.FF(A, B, C, D, temp[12], S[0][0], 0x6b901122L);
        D = this.FF(D, A, B, C, temp[13], S[0][1], 0xfd987193L);
        C = this.FF(C, D, A, B, temp[14], S[0][2], 0xa679438eL);
        B = this.FF(B, C, D, A, temp[15], S[0][3], 0x49b40821L);


        /* Round 2 */
        A = this.GG(A, B, C, D, temp[1], S[1][0], 0xf61e2562L);
        D = this.GG(D, A, B, C, temp[6], S[1][1], 0xc040b340L);
        C = this.GG(C, D, A, B, temp[11], S[1][2], 0x265e5a51L);
        B = this.GG(B, C, D, A, temp[0], S[1][3], 0xe9b6c7aaL);
        A = this.GG(A, B, C, D, temp[5], S[1][0], 0xd62f105dL);
        D = this.GG(D, A, B, C, temp[10], S[1][1], 0x2441453L);
        C = this.GG(C, D, A, B, temp[15], S[1][2], 0xd8a1e681L);
        B = this.GG(B, C, D, A, temp[4], S[1][3], 0xe7d3fbc8L);
        A = this.GG(A, B, C, D, temp[9], S[1][0], 0x21e1cde6L);
        D = this.GG(D, A, B, C, temp[14], S[1][1], 0xc33707d6L);
        C = this.GG(C, D, A, B, temp[3], S[1][2], 0xf4d50d87L);
        B = this.GG(B, C, D, A, temp[8], S[1][3], 0x455a14edL);
        A = this.GG(A, B, C, D, temp[13], S[1][0], 0xa9e3e905L);
        D = this.GG(D, A, B, C, temp[2], S[1][1], 0xfcefa3f8L);
        C = this.GG(C, D, A, B, temp[7], S[1][2], 0x676f02d9L);
        B = this.GG(B, C, D, A, temp[12], S[1][3], 0x8d2a4c8aL);


        /* Round 3 */
        A = this.HH(A, B, C, D, temp[5], S[2][0], 0xfffa3942L);
        D = this.HH(D, A, B, C, temp[8], S[2][1], 0x8771f681L);
        C = this.HH(C, D, A, B, temp[11], S[2][2], 0x6d9d6122L);
        B = this.HH(B, C, D, A, temp[14], S[2][3], 0xfde5380cL);
        A = this.HH(A, B, C, D, temp[1], S[2][0], 0xa4beea44L);
        D = this.HH(D, A, B, C, temp[4], S[2][1], 0x4bdecfa9L);
        C = this.HH(C, D, A, B, temp[7], S[2][2], 0xf6bb4b60L);
        B = this.HH(B, C, D, A, temp[10], S[2][3], 0xbebfbc70L);
        A = this.HH(A, B, C, D, temp[13], S[2][0], 0x289b7ec6L);
        D = this.HH(D, A, B, C, temp[0], S[2][1], 0xeaa127faL);
        C = this.HH(C, D, A, B, temp[3], S[2][2], 0xd4ef3085L);
        B = this.HH(B, C, D, A, temp[6], S[2][3], 0x4881d05L);
        A = this.HH(A, B, C, D, temp[9], S[2][0], 0xd9d4d039L);
        D = this.HH(D, A, B, C, temp[12], S[2][1], 0xe6db99e5L);
        C = this.HH(C, D, A, B, temp[15], S[2][2], 0x1fa27cf8L);
        B = this.HH(B, C, D, A, temp[2], S[2][3], 0xc4ac5665L);


        /* Round 4 */
        A = this.II(A, B, C, D, temp[0], S[3][0], 0xf4292244L);
        D = this.II(D, A, B, C, temp[7], S[3][1], 0x432aff97L);
        C = this.II(C, D, A, B, temp[14], S[3][2], 0xab9423a7L);
        B = this.II(B, C, D, A, temp[5], S[3][3], 0xfc93a039L);
        A = this.II(A, B, C, D, temp[12], S[3][0], 0x655b59c3L);
        D = this.II(D, A, B, C, temp[3], S[3][1], 0x8f0ccc92L);
        C = this.II(C, D, A, B, temp[10], S[3][2], 0xffeff47dL);
        B = this.II(B, C, D, A, temp[1], S[3][3], 0x85845dd1L);
        A = this.II(A, B, C, D, temp[8], S[3][0], 0x6fa87e4fL);
        D = this.II(D, A, B, C, temp[15], S[3][1], 0xfe2ce6e0L);
        C = this.II(C, D, A, B, temp[6], S[3][2], 0xa3014314L);
        B = this.II(B, C, D, A, temp[13], S[3][3], 0x4e0811a1L);
        A = this.II(A, B, C, D, temp[4], S[3][0], 0xf7537e82L);
        D = this.II(D, A, B, C, temp[11], S[3][1], 0xbd3af235L);
        C = this.II(C, D, A, B, temp[2], S[3][2], 0x2ad7d2bbL);
        B = this.II(B, C, D, A, temp[9], S[3][3], 0xeb86d391L);


        this.variable.state[0] += A;
        this.variable.state[1] += B;
        this.variable.state[2] += C;
        this.variable.state[3] += D;


    }

    /*Encode把long数组按顺序拆成byte数组，因为java的long类型是64bit的
     */
    private void Encode(byte[] output, long[] input, int len) {
        for (int i = 0, j = 0; j < len; i++, j += 4) {
            output[j] = (byte) (input[i] & 0xffL);
            output[j + 1] = (byte) ((input[i] >>> 8) & 0xffL);
            output[j + 2] = (byte) ((input[i] >>> 16) & 0xffL);
            output[j + 3] = (byte) ((input[i] >>> 24) & 0xffL);
        }
    }


    /*Decode把byte数组按顺序合成成long数组，因为java的long类型是64bit的
     */
    private void Decode(long[] output, byte[] input, int len) {
        for (int i = 0, j = 0; j < len; i++, j += 4)
            output[i] = this.byte2unsigned(input[j]) | (this.byte2unsigned(input[j + 1]) << 8) | (this.byte2unsigned(input[j + 2]) << 16) | (this.byte2unsigned(input[j + 3]) << 24);
    }

    /* 
      byte2unsigned是把byte按照不考虑正负号的原则的＂升位＂程序，因为java没有unsigned运算 
    */
    public long byte2unsigned(byte B) {
        return B < 0 ? B & 0x7F + 128 : B;
    }

    /*b2Hex()，用来把一个byte类型的数转换成十六进制的ASCII表示
     */
    public String b2Hex(byte ib) {
        String str = (ib >> 4 & 0x0F) <= 9 ? "" + (char) ('0' + (ib >> 4 & 0x0F)) : "" + (char) ('a' - 10 + (ib >> 4 & 0x0F));
        str += (ib & 0X0F) <= 9 ? "" + (char) ('0' + (ib & 0X0F)) : "" + (char) ('a' - 10 + (ib & 0X0F));
        return str;
    }


    void writeResult2FileWithoutSalt() throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(new File("./src/withoutSalt.txt")));
        String waiteEncode = "";
        for (int i = 0; i < 100; i++) {
            waiteEncode += (i % 10);
            bw.write("   id" + i + "  is  : " + waiteEncode + "\n     -->       value is    " + this.MD52Str(waiteEncode) + "\n\n");
            bw.flush();
        }
        bw.close();
    }

    void writeResult2FileWithSalt() throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(new File("./src/withSalt.txt")));

        Random random = new Random();
        long salt;
        String waiteEncode = "";
        for (int i = 0; i < 100; i++) {
            salt = random.nextLong();
            waiteEncode += (i % 10);
            bw.write("   id" + i + "  is  : " + waiteEncode + "   ,salt is   " + salt + "\n     -->      value is   " + this.MD52Str(waiteEncode + salt) + "\n\n");
            bw.flush();
        }
        bw.close();
    }


    public static void main(String args[]) {
        MD5 md5 = new MD5();
        try {
            md5.writeResult2FileWithoutSalt();
            md5.writeResult2FileWithSalt();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("the values have wroten to the file named withoutSalt.txt and withSalt.txt, please check it .");
    }
}  