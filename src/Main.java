// Main.java

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) {
        if (Arrays.asList(args).contains("-help")) {
            printUsage();
            return;
        }

        var argMap = parseArgs(args);

        try {
            if (argMap.containsKey("-encryption")) {
                var truePath = argMap.get("-true");
                var hidePath = argMap.get("-hide");
                var trueKey = argMap.get("-truekey");
                var hideKey = argMap.get("-hidekey");
                var outPath = argMap.get("-out");

                if (truePath == null || hidePath == null || trueKey == null || hideKey == null || outPath == null) {
                    System.out.println("缺少加密模式所需的参数。");
                    printUsage();
                    return;
                }

                var realData = readFile(truePath);
                var fakeData = readFile(hidePath);

                var encryption = new Encryption();
                var encryptedTrue = encryption.encrypt(trueKey, realData);
                var encryptedHide = encryption.encrypt(hideKey, fakeData);

                var container = createContainer(encryptedTrue, encryptedHide, encryption);
                writeFile(outPath, container);
                System.out.println("加密完成，容器文件路径：" + outPath);

            } else if (argMap.containsKey("-Decryption")) {
                var inPath = argMap.get("-in");
                var key = argMap.get("-key");
                var outPath = argMap.get("-out");

                if (inPath == null || key == null || outPath == null) {
                    System.out.println("缺少解密模式所需的参数。");
                    printUsage();
                    return;
                }

                var container = readFile(inPath);
                var encryption = new Encryption();
                var encryptedData = parseContainer(container, encryption);
                if (encryptedData == null) {
                    System.out.println("容器文件格式不正确。");
                    return;
                }

                var decryption = new Decryption();
                try {
                    var decrypted = decryption.decrypt(encryptedData[0], key);
                    writeFile(outPath, decrypted);
                    System.out.println("解密成功！输出文件路径：" + outPath);
                } catch (Exception e) {
                    try {
                        var decrypted = decryption.decrypt(encryptedData[1], key);
                        writeFile(outPath, decrypted);
                        System.out.println("解密成功！输出文件路径：" + outPath);
                    } catch (Exception ex) {
                        System.out.println("解密失败！提供的密钥不正确或数据损坏。");
                    }
                }

            } else {
                System.out.println("无效的模式。");
                printUsage();
            }
        } catch (Exception e) {
            System.out.println("发生错误：" + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        var map = new HashMap<String, String>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("-")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    map.put(args[i], args[i + 1]);
                    i++;
                } else {
                    map.put(args[i], "true");
                }
            }
        }
        return map;
    }

    private static void printUsage() {
        var usage = """
                使用说明:
                  加密模式:
                    java Main -encryption -true <真实文件路径> -hide <假文件路径> -truekey <真实密码> -hidekey <假密码> -out <输出容器文件路径>
                
                  解密模式:
                    java Main -Decryption -in <输入容器文件路径> -key <解密密码> -out <输出文件路径>
                
                  选项:
                    -help              显示此帮助信息。
                
                示例:
                  加密:
                    java Main -encryption -true real.txt -hide fake.txt -truekey RealPass123 -hidekey FakePass456 -out container.dat
                
                  解密:
                    java Main -Decryption -in container.dat -key RealPass123 -out decrypted_real.txt
                """;
        System.out.println(usage);
    }

    private static byte[] createContainer(Encryption.EncryptedData trueData, Encryption.EncryptedData hideData, Encryption encryption) throws IOException {
        var baos = new ByteArrayOutputStream();
        // 真实数据部分
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(trueData.salt());
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(trueData.iv());
        baos.write(intToBytes(trueData.ciphertext().length));
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(trueData.ciphertext());
        // 假数据部分
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(hideData.salt());
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(hideData.iv());
        baos.write(intToBytes(hideData.ciphertext().length));
        baos.write(intToBytes(encryption.getRandomPadding().length));
        baos.write(encryption.getRandomPadding());
        baos.write(hideData.ciphertext());
        return baos.toByteArray();
    }

    private static Encryption.EncryptedData[] parseContainer(byte[] container, Encryption encryption) {
        try {
            var dis = new DataInputStream(new ByteArrayInputStream(container));
            // 真实数据部分
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] saltTrue = new byte[16];
            dis.readFully(saltTrue);
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] ivTrue = new byte[12];
            dis.readFully(ivTrue);
            int lenTrue = dis.readInt();
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] ciphertextTrue = new byte[lenTrue];
            dis.readFully(ciphertextTrue);
            // 假数据部分
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] saltHide = new byte[16];
            dis.readFully(saltHide);
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] ivHide = new byte[12];
            dis.readFully(ivHide);
            int lenHide = dis.readInt();
            dis.readInt(); // padding length
            dis.skipBytes(encryption.getRandomPadding().length);
            byte[] ciphertextHide = new byte[lenHide];
            dis.readFully(ciphertextHide);
            return new Encryption.EncryptedData[]{
                    new Encryption.EncryptedData(saltTrue, ivTrue, ciphertextTrue),
                    new Encryption.EncryptedData(saltHide, ivHide, ciphertextHide)
            };
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    private static byte[] readFile(String path) throws IOException {
        var file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException("文件未找到: " + path);
        }
        var data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int readBytes = fis.read(data);
            if (readBytes != file.length()) {
                throw new IOException("无法读取整个文件: " + path);
            }
        }
        return data;
    }

    //[padding_length (4 bytes)][padding_data][salt (16 bytes)][padding_length (4 bytes)][padding_data][iv (12 bytes)][padding_length (4 bytes)][padding_data][ciphertext_length (4 bytes)][padding_length (4 bytes)][padding_data][ciphertext]

    private static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }
}
