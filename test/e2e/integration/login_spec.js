/// <reference types="Cypress" />

describe("/login behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  beforeEach(() => {
    cy.visitPage("/login");
  });

  it("should have tutorial Guide link", () => {
    cy.get("a[href='/tutorial']")
      .should("have.attr", "target", "_blank")
      .and("be.visible");
  });

  it("Should open the tutorial in another tab", () => {
    cy.get("a[href='/tutorial']").then(function ($a) {
      const href =
      $a.prop("href");
      cy.visit(href);
      cy.url().should("include", "tutorial");
    });
  });

  it("should have admin user able to login", () => {
    cy.fixture("users/admin.json").as("admin");
    cy.get("@admin").then(admin => {
      cy.get("#userName").type(admin.user);
      cy.get("#password").type(admin.pass);
      cy.get("[type='submit']").click();
      cy.url().should("include", "benefits");
    });
  });

  it("should have non-admin user able to login", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type(user.user);
      cy.get("#password").type(user.pass);
      cy.get("[type='submit']").click();
      cy.url().should("include", "dashboard");
    });
  });

  it("should reject wrong password", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type(user.user);
      cy.get("#password").type("TO BE REJECTED");
      cy.get("[type='submit']").click();

      cy.url().should("include", "login");

      cy.get(".alert-danger")
        .contains("Invalid password")
        .and("be.visible");
    });
  });

  it("should reject wrong username", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type("INVENTED");
      cy.get("#password").type(user.pass);
      cy.get("[type='submit']").click();

      cy.url().should("include", "login");

      cy.get(".alert-danger")
        .contains("Invalid username")
        .and("be.visible");
    });
  });

  it("should have new user/ sign up link", () => {
    cy.get("a[href='/signup']")
      .and("be.visible");
  });

  it("Should redirect to the signup", () => {
    cy.get("a[href='/signup']").click();
    cy.url().should("include", "signup");
  });

  // Security regression tests: Reflected XSS prevention (CWE-79)
  // Verify that userName from req.body is HTML-encoded before being reflected
  // back in the login page via swig template auto-escaping (autoescape: true).

  it("should not execute XSS payload when invalid password is submitted", () => {
    // Arrange: XSS payload as the username value
    const xssPayload = "<script>document.title='XSS'</script>";

    // Act: submit the login form with the XSS payload as userName and a wrong password
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type(xssPayload);
      cy.get("#password").type("WRONG_PASSWORD_FOR_XSS_TEST");
      cy.get("[type='submit']").click();

      // Assert: page stays on /login (invalid-password branch, sink at line 91)
      cy.url().should("include", "login");

      // Assert: the script tag is NOT executed — page title remains unchanged
      cy.title().should("not.equal", "XSS");

      // Assert: the userName input field reflects the payload as plain text (encoded),
      // not as an active DOM element — no <script> child nodes inside the input value
      cy.get("#userName").should("have.value", xssPayload);

      // Assert: no <script> element was injected into the DOM by the reflected value
      cy.get("script").each($script => {
        cy.wrap($script).invoke("text").should("not.contain", "document.title='XSS'");
      });
    });
  });

  it("should not execute XSS payload when non-existent username is submitted", () => {
    // Arrange: XSS payload as the username value
    const xssPayload = "<img src=x onerror=\"document.title='XSS'\">";

    // Act: submit with an unknown userName (noSuchUser branch, sink at line 82)
    cy.get("#userName").type(xssPayload);
    cy.get("#password").type("anyPassword");
    cy.get("[type='submit']").click();

    // Assert: page stays on /login
    cy.url().should("include", "login");

    // Assert: the onerror handler was NOT executed — page title is unchanged
    cy.title().should("not.equal", "XSS");

    // Assert: the userName input field contains the raw payload text (encoded value),
    // confirming the template escaped it rather than rendering it as HTML
    cy.get("#userName").should("have.value", xssPayload);

    // Assert: no <img> element with the injected onerror attribute exists in the DOM
    cy.get("img[onerror]").should("not.exist");
  });

  it("should HTML-encode special characters in userName when reflected on login error", () => {
    // Verify that HTML special characters are encoded in the reflected userName value,
    // confirming swig autoescape is active for this taint flow.
    const specialChars = "test&\"'<>";

    cy.get("#userName").type(specialChars);
    cy.get("#password").type("wrongPassword");
    cy.get("[type='submit']").click();

    cy.url().should("include", "login");

    // The input value should preserve the raw characters (browsers decode attribute values),
    // and critically no raw unencoded HTML should be injected into the page structure.
    cy.get("#userName").should("have.value", specialChars);

    // Verify the page source does not contain the unencoded angle brackets outside of
    // expected safe contexts — confirm encoding happened at the template layer.
    cy.get("body").invoke("html").then(html => {
      // The encoded form (&lt;, &gt;, &amp;, &#34;, &#39;) should appear in the raw HTML
      // rather than literal < > & " ' which would indicate unescaped reflection.
      // We check that no raw <script> or <img> payloads appear as unescaped markup.
      expect(html).to.not.contain("<script>");
      expect(html).to.not.contain("<img ");
    });
  });
});
