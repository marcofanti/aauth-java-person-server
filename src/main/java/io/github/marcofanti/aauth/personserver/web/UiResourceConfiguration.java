package io.github.marcofanti.aauth.personserver.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Serve the static console under {@code /ui/} — the portal UI by default, or the original
 * PS / AS consoles when running a standalone profile (mirrors the FastAPI StaticFiles
 * mounts, including {@code /ui/} → {@code index.html}).
 */
@Configuration
public class UiResourceConfiguration implements WebMvcConfigurer {

    private final String uiRoot;

    public UiResourceConfiguration(Environment environment) {
        if (environment.matchesProfiles("ps")) {
            this.uiRoot = "classpath:/ui-ps/";
        } else if (environment.matchesProfiles("agent-server")) {
            this.uiRoot = "classpath:/ui-as/";
        } else {
            this.uiRoot = "classpath:/ui-portal/";
        }
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/ui/**").addResourceLocations(uiRoot);
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/ui", "/ui/index.html");
        registry.addRedirectViewController("/ui/", "/ui/index.html");
    }
}
