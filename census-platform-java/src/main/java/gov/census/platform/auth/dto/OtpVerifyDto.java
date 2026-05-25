package gov.census.platform.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpVerifyDto(
        @NotBlank
        @Pattern(regexp = "^\\+\\d{7,15}$")
        String phoneNumber,

        @NotBlank
        @Pattern(regexp = "^\\d{6}$", message = "OTP must be exactly 6 digits")
        String otpCode
) {}
