package core.jwtauthenticationlib.Dto;

import lombok.Data;

@Data
public class LoginDto {
    private String username;
    private String password;
}
