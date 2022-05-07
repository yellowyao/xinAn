package suep.yao.DES;

import java.util.Scanner;

public class test {
    public static void main(String[] args) {

        DES des = new DES();
        Scanner scanner = new Scanner(System.in);
        Scanner scanner1 = new Scanner(System.in);
        //输入1加密，2解密，0退出
        int flag = 3;
        while (flag != 0) {
            System.out.println("请输入1加密，2解密，0退出");
            flag = scanner1.nextInt();
            if (flag == 1) {
                System.out.println("请输入明文：");
                String str = scanner.nextLine();
                System.out.println("请输入密钥：");
                String key = scanner.nextLine();
                String ciphertext = des.getCiphertext(str, key);
                System.out.println("密文：");
                System.out.println(ciphertext);
            } else if (flag == 2) {
                System.out.println("请输入密文：");
                String ciphertext1 = scanner.nextLine();
                //输入密钥
                System.out.println("请输入密钥：");
                String key1 = scanner.nextLine();
                //明文为
                System.out.println("明文：");
                System.out.println(des.Decrypt(ciphertext1, key1));
            }
        }


    }
}
