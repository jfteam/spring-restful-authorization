package com.scienjus.authorization.manager.impl;

import com.scienjus.authorization.manager.TokenManager;
import com.scienjus.authorization.model.TokenModel;
import com.scienjus.config.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 通过Redis存储和验证token的实现类
 *
 * @author ScienJus
 * @date 2015/7/31.
 * @see com.scienjus.authorization.manager.TokenManager
 */
@Component
public class RedisTokenManager implements TokenManager {

    private final RedisTemplate<Long, String> redisTemplate;

    /**
     * 通过构造方法注入
     *
     * @param redisTemplate
     */
    public RedisTokenManager(RedisTemplate<Long, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.redisTemplate.setKeySerializer(new JdkSerializationRedisSerializer());
    }

    public TokenModel createToken(long userId) {
        //使用uuid作为源token
        String token = UUID.randomUUID().toString().replace("-", "");
        TokenModel model = new TokenModel(userId, token);
        //存储到redis并设置过期时间
        redisTemplate.boundValueOps(userId).set(token, Constants.TOKEN_EXPIRES_HOUR, TimeUnit.HOURS);
        return model;
    }

    public TokenModel getToken(String authentication) {
        if (!StringUtils.hasText(authentication)) {
            return null;
        }
        String[] param = authentication.split("_");
        if (param.length != 2) {
            return null;
        }
        //使用userId和源token简单拼接成的token，可以增加加密措施
        long userId = Long.parseLong(param[0]);
        String token = param[1];
        return new TokenModel(userId, token);
    }

    public boolean checkToken(TokenModel model) {
        if (model == null) {
            return false;
        }
        String token = redisTemplate.boundValueOps(model.getUserId()).get();
        if (StringUtils.hasText(token) && token.equals(model.getToken())) {
            //如果验证成功，说明此用户进行了一次有效操作，延长token的过期时间
            redisTemplate.boundValueOps(model.getUserId()).expire(Constants.TOKEN_EXPIRES_HOUR, TimeUnit.HOURS);
            return true;
        }
        return false;
    }

    public void deleteToken(long userId) {
        redisTemplate.delete(userId);
    }
}
