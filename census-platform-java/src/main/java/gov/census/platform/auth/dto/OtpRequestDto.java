package gov.census.platform.auth.dto;

import gov.census.platform.auth.service.OtpService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record OtpRequestDto(
        @NotBlank
        @Pattern(regexp = "^\\+\\d{7,15}$", message = "Phone number must include country code (e.g. +9647XXXXXXXX)")
        String phoneNumber,

        OtpService.OtpChannel channel,

        @Size(min = 2, max = 5)
        @Pattern(regexp = "^[a-z]{2,5}$")
        String locale
) {
    public OtpRequestDto {
        if (channel == null) channel = OtpService.OtpChannel.SMS;
        if (locale == null)  locale  = "ar";
    }
}
