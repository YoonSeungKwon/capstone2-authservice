package yoon.docker.authService.enums;


public enum Role {

    GUEST("ROLE_ANONYMOUS"),
    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    private final String key;

    Role(String key){
        this.key = key;
    }

    public String getRoleKey(){
        return this.key;
    }

}