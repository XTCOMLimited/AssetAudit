package com.xt.asset.audit.util;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptionUtils {
    /** Merkel Tree 节点位置:left */
    private static final String TREE_NODE_LOCATION_LEFT = "left";

    public static void main(String[] args) {
        // 替换下载的资产证明json文件
        String proofJson = "{\n" +
                "    \"auditId\": 1733190574176,\n" +
                "    \"auditTime\": 1733190574176,\n" +
                "    \"encryptUid\": \"0da7bba96edbbe6b44ab0dc353a0717b998880a46d2cf94ecac59be876b1009c\",\n" +
                "    \"balances\": {\n" +
                "      \"BTC\": \"300\"\n" +
                "    },\n" +
                "    \"rootHash\": \"d634e0945a01f8b0e63f2198e25697741d89ab6619602bd323d683359928b6af\",\n" +
                "    \"leafHash\": \"ca933a49e29b4d3663c50c4fd2044ef63c90bc40058366056a3fe88085325fef\",\n" +
                "    \"peerList\": [\n" +
                "      \"5c0c9412da606bd7dcf3c1900a54d729d42cdc56069cf022a2b649923a9803ac:left\",\n" +
                "      \"06ccf8b08e0d615f05749e1c1a1fa09b22698294e50281724141d144a3d7261b:left\",\n" +
                "      \"6facc4a0d66b75c1d83d33ea9f37956137650365f70e9f2755167c0fe2af35ea:left\",\n" +
                "      \"5758f50dfb8097e75706664b8ac7b0c4d17432a0357cfaa0f535c75e9438659c:left\",\n" +
                "      \"41f024733d426a9962b6617f5fa9c09eeebe25c55e291d46fc990813639c1b2c:left\",\n" +
                "      \"9548e5357208ed40b8f07e3deb1a7a8d8ebf275b54954661ab28cb49d5d43f20:right\",\n" +
                "      \"96a1a8b5c0866add75dacac844e3aa0c8c1861cf70cf04900e62fe9a5db6a01f:right\",\n" +
                "      \"abee80979aa58e3ef3e27ac911354e7363f497e388016d4ff67b21f07c4d9c4a:right\",\n" +
                "      \"fc8afb16283bc3f0baccb3ae27edb2dbd6a15ee9454996f7f0019b86dccc7982:right\",\n" +
                "      \"0960971761f160f0073425d8e604cc06fe54cf395824ae0304fa2391c165b8e2:right\",\n" +
                "      \"46e874a746af15b5e6af70d2dfc5fdba99e263d5ac258171fa9ab434ffd0c2b3:right\",\n" +
                "      \"04b7dfcccf5a6afc05d4c5418cf93de897211813aeccb59791a821e3b8a47730:right\",\n" +
                "      \"67f2d0cbd3d9ffdca5cd89004aca407bbe7b4f7156cc2670efd6a5ab8c664d65:right\",\n" +
                "      \"4b32fed6fe467ecbc1e85f9061314c5107f722f16577cc3ef1e6b27e5dc81404:right\",\n" +
                "      \"77762c78de8fc5beb4cb0ff7c03581eeeee5505305ece9c8bfdc8cbdec2d87b3:right\",\n" +
                "      \"d41fa1407a3e2419fae3c21b905673944cbbea738214f38e1a02bc19209b42d4:right\",\n" +
                "      \"96cb457baa24ffea8bfa161a8ba2896bb3820c519ff59c55ab5801346fe7f1a9:right\",\n" +
                "      \"a8d95305f06be6dcc60f3309700701d813d019f672bcf89ce01f97cec07e8d16:right\",\n" +
                "      \"715b37c73580b695111c7a376282cb35674104028b5d2d7e658fc18b4e0a14ce:right\",\n" +
                "      \"543cedd0eed3de3db9fa7f73c2506bc368ade6609d66155a38cab034ba82a334:right\",\n" +
                "      \"f4b9eecb19377eeda335cc47ed870c950111b51ea9b37a9d8ae391f2f2cf9aa8:right\",\n" +
                "      \"95a613b95218166e97dd5ad34e4a22e9709112a028709d27ef39568b145c9459:right\"\n" +
                "    ]\n" +
                "  }";

        // 开始验证
        verifyProofFile(JSONObject.parseObject(proofJson));
    }

    public static String sha256ToHex(String input) {
        try {
            // 创建 SHA-256 MessageDigest 实例
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 计算 SHA-256 哈希值
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            // 转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    public static void  verifyProofFile(JSONObject proofJson){
        JSONObject info = new JSONObject();
        info.put("encryptUid",proofJson.getString("encryptUid"));
        info.put("auditId",proofJson.getLong("auditId"));
        info.put("balances",proofJson.getJSONObject("balances"));
        if(proofJson.getString("leafHash").equals(sha256ToHex(info.toJSONString()))){
            System.out.println("Leaf node hash verify success :" + proofJson.getString("leafHash"));
        }

        JSONArray peerArray = proofJson.getJSONArray("peerList");
        String currentHash = proofJson.getString("leafHash");
        for(int i = 0; i < peerArray.size(); i++){
            String peerHash = peerArray.getString(i).split(":")[0];
            boolean isLeft = TREE_NODE_LOCATION_LEFT.equals(peerArray.getString(i).split(":")[1]);

            String value = isLeft ? peerHash + currentHash : currentHash + peerHash;
            currentHash = EncryptionUtils.sha256ToHex(value);
        }

        if(currentHash.equals(proofJson.getString("rootHash"))){
            System.out.println("Root node hash verify success :" + currentHash);
        }
    }
}
