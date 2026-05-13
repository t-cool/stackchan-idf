idf_component_register(
    SRCS
        "app_main.cpp"
        "audio_codec.cpp"
        "render_task.cpp"
        "servo_task.cpp"
        "speech.cpp"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        board
        scs_servo
        avatar
        M5Unified
        M5GFX
        esp_timer
        driver
)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_20)
