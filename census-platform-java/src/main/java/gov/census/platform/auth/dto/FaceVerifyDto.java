package gov.census.platform.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record FaceVerifyDto(
        @NotBlank
        @Size(min = 100, message = "Image data too short")
        String imageBase64,   // JPEG/PNG — processed in-memory, never stored

        @NotBlank
        @Size(min = 32)
        String sessionToken
) {}
