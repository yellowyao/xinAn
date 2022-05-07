package suep.yao.SHA_1;

import java.util.Scanner;

public class sha {


    public static void main(String[] args) {
        sha sha = new sha();
        //输入明文
        System.out.println("请输入明文：");
        String s = new Scanner(System.in).nextLine();
        //输出密文
        System.out.println("SHA-1加密结果为:");
        System.out.println(sha.sha1(s));


//11000010110001001100011100000000


    }

    //将字节变成8位二进制
    public static String byteTo8(byte b) {
        String s = Integer.toBinaryString(b);
        while (s.length() < 8) {
            s = "0" + s;
        }
        return s;
    }

    //16进制转换成十进制
    public static int hexToDec(String s) {
        int sum = 0;
        for (int i = 0; i < s.length(); i++) {
            sum = sum * 16 + Integer.parseInt(s.substring(i, i + 1), 16);
        }
        return sum;
    }

    //H0

    private String[] H0 = {"67452301", "EFCDAB89", "98BADCFE", "10325476", "C3D2E1F0"};
    //K
    private String[] K = {"5A827999", "6ED9EBA1", "8F1BBCDC", "CA62C1D6"};

    //SHA-1加密算法
    public String sha1(String str) {
        //初始化a,b,c,d,e
        Long a = Long.parseLong(this.H0[0], 16);
        Long b = Long.parseLong(this.H0[1], 16);
        Long c = Long.parseLong(this.H0[2], 16);
        Long d = Long.parseLong(this.H0[3], 16);
        Long e = Long.parseLong(this.H0[4], 16);

        Long[] HI = new Long[5];
        HI[0] = a;
        HI[1] = b;
        HI[2] = c;
        HI[3] = d;
        HI[4] = e;
        //获取512bits的消息
        String[] extracted512Bits = this.extracted512Bits(str);
        //每个512bit的运算
        for (String bit_512 : extracted512Bits) {
            String[] W = this.operation512Bits(bit_512);
            for (int i = 0; i < 80; i++) {
                long w = Long.parseLong(W[i], 16);
                //T函数
                Long T = this.ROTL(a, 5) + this.F(b, c, d, i) + e + w + Long.parseLong(this.K[i / 20], 16);
                T = this.fixHex(T);
                e = d;
                d = c;
                //c模2^32
                c = this.ROTL(b, 30);
                b = a;
                a = T;
                HI[0] = this.fixHex(HI[0] + a);
                HI[1] = this.fixHex(HI[1] + b);
                HI[2] = this.fixHex(HI[2] + c);
                HI[3] = this.fixHex(HI[3] + d);
                HI[4] = this.fixHex(HI[4] + e);
            }
            a = HI[0];
            b = HI[1];
            c = HI[2];
            d = HI[3];
            e = HI[4];


        }
        //返回结果
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < 5; i++) {
            buf.append(this.addZero(Long.toHexString(HI[i])));
        }
        return buf.toString();
    }

    /**
     * 固定十六进制的位数
     */
    private Long fixHex(Long l) {
        String s = Long.toHexString(l);
        while (s.length() > 8) {
            s = s.substring(s.length() - 8);
        }
        return Long.parseLong(s, 16);
    }

    /**
     * F函数
     */
    private Long F(Long x, Long y, Long z, int i) {
        if (i < 20) {
            return (x & y) | (x & z);
        } else if (i < 40) {

            return this.fixHex(x + y + z);
        } else if (i < 60) {
            return (x & y) | (x & z) | (y & z);
        } else {
            return this.fixHex(x + y + z);

        }
    }

    /**
     * 每个512bit的运算
     */
    public String[] operation512Bits(String str) {
        String[] W = new String[80];
        //初始化W,W[0]到W[15]
        for (int i = 0; i < str.length() / 32; i++) {
            W[i] = str.substring(i * 32, (i + 1) * 32);
        }
        //W[16]到W[79]
        for (int i = str.length() / 32; i < 80; i++) {
            W[i] = this.ROTL(this.XOR(this.XOR(this.XOR(W[i - 3], W[i - 8]), W[i - 14]), W[i - 16]), 1);
        }
        //将W[0]到W[79]转换成8位16进制
        for (int i = 0; i < 80; i++) {
            //32位的二进制字符串
            String er = W[i];
            StringBuffer stringBuffer = new StringBuffer();
            for (int i1 = 0; i1 < er.length() / 4; i1++) {
                String substring = er.substring(i1 * 4, (i1 + 1) * 4);
                stringBuffer.append(Integer.toHexString(Integer.parseInt(substring, 2)));
            }
            W[i] = stringBuffer.toString();
        }
        return W;
    }

    /**
     * 异或运算
     */
    public String XOR(String str1, String str2) {

        Long l1 = Long.parseLong(str1, 2);
        Long l2 = Long.parseLong(str2, 2);
        Long l = l1 + l2;
        String s = Long.toBinaryString(l);
        if (s.length() > 32) {
            s = s.substring(s.length() - 32);
        } else if (s.length() < 32) {
            int i = 32 - s.length();
            for (int j = 0; j < i; j++) {
                s = "0" + s;
            }
        }
        return s;
    }

    /***
     * ROTL函数
     * @param str
     * @return
     */
    public String ROTL(String str, int i) {
        //左移
        String substring = str.substring(i);
        String substring1 = str.substring(0, i);
        return substring + substring1;
    }

    /***
     * ROTR函数
     * @param i
     * @param j
     * @return
     */
    public Long ROTL(Long i, int j) {
        //循环左移i位
        String string = Long.toBinaryString(i);

        if (string.length() < 32) {
            int length = string.length();
            for (int i1 = 0; i1 < 32 - length; i1++) {
                string = "0" + string;
            }
        }
        String substring = string.substring(j);
        String substring1 = string.substring(0, j);
        long l = Long.parseLong((substring + substring1), 2);
        return this.fixHex(l);
    }

    /**
     * 补全位数 --8
     *
     * @param str
     * @return
     */
    public String addZero(String str) {
        if (str.length() < 8) {
            int i = 32 - str.length();
            for (int j = 0; j < i; j++) {
                str = "0" + str;
            }
        }
        return str;

    }

    /**
     * 转化为512bit
     *
     * @param str
     * @return
     */
    private String[] extracted512Bits(String str) {
        StringBuffer buf = new StringBuffer();
        //将字符串转换成字节数组
        byte[] strBytes = str.getBytes();
        for (byte strByte : strBytes) {
            buf.append(byteTo8(strByte));
        }
        int length = buf.length();
        //计算需要补充的位数
        int needLength = this.getNeedLength(length);
        //补充1
        buf.append("1");
        //补充0
        for (int i = 0; i < needLength - 1; i++) {
            buf.append("0");
        }
        //计算消息长度
        String lengthStr = this.intTo64(length);
        //补充消息长度
        buf.append(lengthStr);
        String s = buf.toString();
        int length1 = s.length();
        String[] strings = new String[length1 / 512];
        for (int i = 0; i < length1 / 512; i++) {
            strings[i] = s.substring(i * 512, (i + 1) * 512);
        }
        return strings;
    }

    /**
     * 计算要补充的位数
     */
    public int getNeedLength(int length) {
        int L = length % 512;
        return 512 - 64 - L;
    }

    //将输入的int转为64位二进制
    public String intTo64(int i) {
        String s = Integer.toBinaryString(i);
        while (s.length() < 64) {
            s = "0" + s;
        }
        return s;
    }
}
