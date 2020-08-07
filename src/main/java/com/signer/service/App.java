/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.signer.service;

import java.util.Base64;

import com.signer.service.impl.JsonConfiguration;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

public class App {
	private static final String SIGNER_APP_PATH = "signer";
	private static final String SIGNER_VERSION_PATH = "v1";
	private static final String SIGNER_KEYPAIRS_PATH = "key_pairs";
	private static final String SIGNER_SIGNATURES_PATH = "signatures";
	
	private Configuration config;
	private AuthorizationHandler authHandler;
	private KeyPairsService keyPairsService;
	private SignaturesService signaturesService;
	
    public static void main(String[] args) throws Exception {
    	App app = new App();
    	app.executeApp();
    }
    
    public App() throws Exception {
    	config = new JsonConfiguration();
    	authHandler = new AuthorizationHandler(config.getJwsKey());
    	keyPairsService = new KeyPairsService();
    	signaturesService = new SignaturesService();
    }
    
    public void executeApp() throws Exception {
    	Vertx vertx = Vertx.vertx();
		HttpServer server = vertx.createHttpServer();

		Router mainRouter = Router.router(vertx);

		Router oauthRouter = Router.router(vertx);
		oauthRouter.route().handler(BodyHandler.create());
		oauthRouter.route().handler(routingContext -> {
			routingContext.response().putHeader("content-type", "application/json");
			String authHeader = routingContext.request().getHeader("Authorization");
			
			try {
				boolean authz = authHandler.authorize(authHeader);
				if(!authz) {
					JsonObject json = new JsonObject().put("error", "Not Authorized");
					routingContext.response().setStatusCode(401).end(json.toString());
					return;
				}
			} catch (BadRequestException e) {
				JsonObject json = new JsonObject().put("error", "Bad request").put("description", e.getMessage());
				routingContext.response().setStatusCode(400).end(json.toString());
			} catch (Exception e) {
				JsonObject json = new JsonObject().put("error", "Internal server error").put("description", e.getMessage());
				routingContext.response().setStatusCode(500).end(json.toString());
				e.printStackTrace();
			}
			routingContext.next();
		});
		
		mainRouter.mountSubRouter("/" + SIGNER_APP_PATH + "/" + SIGNER_VERSION_PATH, oauthRouter);
		oauthRouter.route(HttpMethod.POST, "/" + SIGNER_KEYPAIRS_PATH).handler(routingContext -> {
			try {
				String response = keyPairsService.generateKeyPair(routingContext.getBodyAsString());
				routingContext.response().end(response);
			} catch(BadRequestException e) {
				JsonObject json = new JsonObject().put("error", "Bad request").put("description", e.getMessage());
				routingContext.response().setStatusCode(400).end(json.toString());
			} catch(Exception e) {
				JsonObject json = new JsonObject().put("error", "Internal server error").put("description", e.getMessage());
				routingContext.response().setStatusCode(500).end(json.toString());
				e.printStackTrace();
			}
		});
		
		oauthRouter.route(HttpMethod.POST, "/" + SIGNER_SIGNATURES_PATH).handler(routingContext -> {
			try {
				String response = signaturesService.sign(routingContext.getBodyAsString());
				routingContext.response().end(response);
			} catch(BadRequestException e) {
				JsonObject json = new JsonObject().put("error", "Bad request").put("description", e.getMessage());
				routingContext.response().setStatusCode(400).end(json.toString());
			} catch(Exception e) {
				JsonObject json = new JsonObject().put("error", "Internal server error").put("description", e.getMessage());
				routingContext.response().setStatusCode(500).end(json.toString());
				e.printStackTrace();
			}
		});

		server.requestHandler(mainRouter);

		server.listen(config.getPort());
		System.out.println("Signer service listening on port " + config.getPort());
    }
}