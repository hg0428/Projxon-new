var csrfToken,
	csrfTokenElement,
	dataCollectionForm,
	collectionInstructions,
	dataCollectionDiv;

async function API(endpoint, data) {
	let response = await fetch(endpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-CSRFToken": csrfToken,
		},
		body: JSON.stringify(data),
	});
	let json = await response.json();
	if (json["csrf-token"]) {
		csrfToken = json["csrf-token"];
		csrfTokenElement.value = json["csrf-token"];
	}
	return json;
}
window.addEventListener("load", (event) => {
	csrfTokenElement = document.getElementById("csrf-token");
	csrfToken = csrfTokenElement.value;
	dataCollectionForm = document.getElementById("data-collection-form");
	collectionInstructions = document.getElementById("collection-instructions");
	dataCollectionDiv = document.getElementById("data-collection-div");
	initAuth();
});

function initAuth() {
	let session;
	API("/api/begin-registration", {
		"csrf-token": csrfToken,
	}).then((json) => {
		session = json["session-id"];
		let readData = collect(json["collect"]);
		dataCollectionForm.addEventListener("submit", (event) => {
			event.preventDefault();
			let data = readData();
			console.log(data);
			API("/api/registration/send", {
				"csrf-token": csrfToken,
				"session-id": session,
				data,
			}).then((json) => {
				document.getElementById("messages").innerText =
					json["messages"].join("\n");
				readData = collect(json["collect"]);
			});
		});
		// On submit, send the data.
	});
}
function collect(what) {
	console.log(what);
	if (what === "primary-email") {
		collectionInstructions.innerText = "Enter your email address:";
		dataCollectionDiv.innerHTML = "";
		let emailElement = $("input")
			.attributes({
				type: "email",
				name: "email",
				placeholder: "Email",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		enableEmailValidation(emailElement);
		return () => [emailElement.value];
	} else if (what === "first-name") {
		collectionInstructions.innerText = "Enter your first name:";
		dataCollectionDiv.innerHTML = "";
		let firstNameElement = $("input")
			.attributes({
				type: "text",
				name: "first-name",
				placeholder: "First Name",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		return () => [firstNameElement.value];
	} else if (what === "last-name") {
		collectionInstructions.innerText = "Enter your last name:";
		dataCollectionDiv.innerHTML = "";
		let lastNameElement = $("input")
			.attributes({
				type: "text",
				name: "last-name",
				placeholder: "Last Name",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		return () => [lastNameElement.value];
	} else if (what === "full-name") {
		collectionInstructions.innerText = "Enter your name:";
		dataCollectionDiv.innerHTML = "";
		let firstNameElement = $("input")
			.attributes({
				type: "text",
				name: "first-name",
				placeholder: "First Name",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		let lastNameElement = $("input")
			.attributes({
				type: "text",
				name: "last-name",
				placeholder: "Last Name",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		return () => [firstNameElement.value, lastNameElement.value];
	} else if (what === "primary-phone") {
		collectionInstructions.innerText = "Enter your phone number:";
		dataCollectionDiv.innerHTML = "";
		let phoneElement = $("input")
			.attributes({
				type: "tel",
				name: "phone",
				placeholder: "Phone",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		enablePhoneValidation(phoneElement);
		return () => [phoneElement.value];
	} else if (what === "birthday") {
		collectionInstructions.innerText = "Enter your birthday:";
		dataCollectionDiv.innerHTML = "";
		let yearElement = $("input")
			.attributes({
				type: "number",
				name: "year",
				placeholder: "Year",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		let monthElement = $("input")
			.attributes({
				type: "number",
				name: "month",
				placeholder: "Month",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		let dayElement = $("input")
			.attributes({
				type: "number",
				name: "day",
				placeholder: "Day",
				required: true,
			})
			.appendTo(dataCollectionDiv);
		return () => [yearElement.value, monthElement.value, dayElement.value];
	} else if (what === "country") {
		collectionInstructions.innerText = "Select your country.";
		dataCollectionDiv.innerHTML = "";
		let countrySelector = document.getElementById("country-selector");
		countrySelector.style.display = "block";
		return () => {
			countrySelector.style.display = "none";
			return [countrySelector.value];
		};
	} else if (what === "register-passkey") {
		isWebAuthnAvailable().then(() => {
			let passkeyElement = $("button")
				.text("Register Passkey")
				.appendTo(dataCollectionDiv);
			passkeyElement.addEventListener("click", (event) => {
				event.preventDefault();
				registerPasskey();
			});
		});
	}
}
async function isWebAuthnAvailable() {
	// Availability of `window.PublicKeyCredential` means WebAuthn is usable.
	// `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
	// `​​isConditionalMediationAvailable` means the feature detection is usable.
	if (
		window.PublicKeyCredential &&
		PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
		PublicKeyCredential.isConditionalMediationAvailable
	) {
		// Check if user verifying platform authenticator is available.
		let results = await Promise.all([
			PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
			PublicKeyCredential.isConditionalMediationAvailable(),
		]);
		if (results.every((r) => r === true)) {
			return true;
		}
	}
	return false;
}
async function registerPasskey() {
	const publicKeyCredentialCreationOptions = {
		challenge: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
		rp: {
			name: "Projxon",
			id: "localhost:8080",
		},
		user: {
			id: new ArrayBuffer(16),
			name: "john78",
			displayName: "John",
		},
		pubKeyCredParams: [
			{ alg: -7, type: "public-key" },
			{ alg: -257, type: "public-key" },
		],
		excludeCredentials: [
			{
				id: new ArrayBuffer(16),
				type: "public-key",
				transports: ["internal"],
			},
		],
		authenticatorSelection: {
			authenticatorAttachment: "platform",
			requireResidentKey: true,
		},
	};
	const credential = await navigator.credentials.create({
		publicKey: publicKeyCredentialCreationOptions,
	});
	console.log(credential);
}
const emailValidationRegex =
	/(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;
function enableEmailValidation(element) {
	element.addEventListener("input", (event) => {
		let isValid = emailValidationRegex.test(element.value);
		if (isValid) {
			element.removeClass("invalid");
			element.class("valid");
		} else {
			element.removeClass("valid");
			element.class("invalid");
		}
	});
}
function enablePhoneValidation(element) {
	element.addEventListener("input", (event) => {
		let isValid = libphonenumber.isValidPhoneNumber(element.value, "US");
		if (isValid) {
			element.removeClass("invalid");
			element.class("valid");
		} else {
			element.removeClass("valid");
			element.class("invalid");
		}
	});
	return element;
}
