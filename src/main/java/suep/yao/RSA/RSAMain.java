package suep.yao.RSA;

import java.util.Map;
import java.util.Scanner;

public class RSAMain {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        while (true) {

            System.out.println("是否生成密钥对？(y/n)");
            String input = scanner.nextLine();
            if (input.equals("y")) {
                System.out.println("生成密钥对...");
                Map<String, Object> Keys = RSAUtil.initKey();
                System.out.println("公钥：" + RSAUtil.getpublicKey(Keys).getModulus());
                System.out.println("私钥：" + RSAUtil.getPrivateKey(Keys));
                System.out.println("生成密钥对完成！");
                //输入明文
                System.out.println("请输入明文：");
                String plaintext = scanner.nextLine();
                //加密
                byte[] encrypt = RSAUtil.encrypt(plaintext.getBytes(), RSAUtil.getpublicKey(Keys));
                System.out.println("密文：" + new String(encrypt));
                //解密
                byte[] decrypt = RSAUtil.decrypt(encrypt, RSAUtil.getPrivateKey(Keys));
                System.out.println("解密后的明文：" + new String(decrypt));


            } else {
                System.out.println("请输入公钥：");
                String publicKey = scanner.nextLine();

                System.out.println("输入明文：");
                String plainText = scanner.nextLine();

            }
        }


    }
}
