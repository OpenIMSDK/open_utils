package token_verify

import (
	utils "github.com/OpenIMSDK/open_utils"
	"github.com/OpenIMSDK/open_utils/constant"
	"github.com/golang-jwt/jwt/v4"
	"strings"
	"time"
)

type Claims struct {
	UserID string
	jwt.RegisteredClaims
}

func BuildClaims(userID string, ttlDay int64) Claims {
	now := time.Now()
	before := now.Add(-time.Minute * 5)
	return Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlDay*24) * time.Hour)), //Expiration time
			IssuedAt:  jwt.NewNumericDate(now),                                           //Issuing time
			NotBefore: jwt.NewNumericDate(before),                                        //Begin Effective time
		}}
}

func CreateToken(UserID string, ttlDay int64, accessSecret string) (string, error) {
	claims := BuildClaims(UserID, ttlDay)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(accessSecret))
	if err != nil {
		return "", utils.Wrap(err, "")
	}
	return tokenString, utils.Wrap(err, "")
}

func secret(accessSecret string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return []byte(accessSecret), nil
	}
}

func GetUserIDFromToken(tokensString string, accessSecret string) (string, error) {
	token, err := jwt.ParseWithClaims(tokensString, &Claims{}, secret(accessSecret))
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return "", utils.Wrap(constant.ErrTokenMalformed, "")
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return "", utils.Wrap(constant.ErrTokenExpired, "")
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return "", utils.Wrap(constant.ErrTokenNotValidYet, "")
			} else {
				return "", utils.Wrap(constant.ErrTokenUnknown, "")
			}
		} else {
			return "", utils.Wrap(constant.ErrTokenNotValidYet, "")
		}
	} else {
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			return claims.UserID, nil
		}
		return "", utils.Wrap(constant.ErrTokenNotValidYet, "")
	}
}

func CreateChatToken(userId string, ttlDay int64, accessSecret string) (string, error) {
	//m := md5.New()
	//m.Write([]byte(fmt.Sprintf("%d-%d-%d-%s-%f", rand.Int(), rand.Uint64(), time.Now().UnixNano(), userId, rand.Float64())))
	//token := hex.EncodeToString(m.Sum(nil))
	//err := db.DB.Rdb.RDB.Set(context.Background(), "chat_token:"+token, userId, time.Hour*24*time.Duration(ttlDay)).Err()
	//if err != nil {
	//	return "", utils.Wrap(err, "")
	//}
	//return token, nil
	return CreateToken("user-"+userId, ttlDay, accessSecret)
}

func GetChatToken(token string, accessSecret string) (string, error) {
	//userID, err := db.DB.Rdb.RDB.Get(context.Background(), "chat_token:"+token).Result()
	//if err != nil {
	//	return "", utils.Wrap(err, "")
	//}
	userId, err := GetUserIDFromToken(token, accessSecret)
	if err != nil {
		return "", err
	}
	userId = strings.Replace(userId, "user-", "", 1)
	return userId, nil
}
