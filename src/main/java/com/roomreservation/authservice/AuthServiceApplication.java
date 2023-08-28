package com.roomreservation.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Collections;

@EnableSwagger2
@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

	@Bean
	public Docket get() {
		return new Docket(DocumentationType.SWAGGER_2)
				.select()
				.apis(RequestHandlerSelectors.any())
				.paths(PathSelectors.any())
				.build()
				.apiInfo(createApiInfo());
	}

	private ApiInfo createApiInfo() {
		return new ApiInfo(
				"RoomReservation.AuthService API",
				"Część projektu \"Room Reservation\",będzie odpowiedzialny za autoryzację użytkowników w systemie.",
				"0.0.1",
				"",
				new Contact("Michal Bednarczyk", "", "michal.bednarczyk1993@gmail.com"),
				"Apache License 2.0",
				"https://github.com/michalbednarczyk1993/RoomReservation.AuthService/blob/master/LICENSE",
				Collections.emptyList()
		);
	}

}
