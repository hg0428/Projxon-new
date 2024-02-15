class El {
	constructor(type) {
		this.element = document.createElement(type);
	}
	appendTo(element) {
		element.appendChild(this.element);
		return this;
	}
	prependTo(element) {
		element.prepend(this.element);
		return this;
	}
	class(classes) {
		this.element.classList.add(classes);
		return this;
	}
	removeClass(classes) {
		this.element.classList.remove(classes);
		return this;
	}
	id(id) {
		this.element.id = id;
		return this;
	}
	text(text) {
		this.element.innerText = text;
		return this;
	}
	content(content) {
		if (typeof content === "string") {
			this.innerHTML = content;
		} else {
			for (let element of content) {
				if (element instanceof $) {
					this.element.appendChild(element.element);
				} else {
					this.element.appendChild(document.createTextNode(element));
				}
			}
		}
		return this;
	}
	attributes(attrs) {
		for (let attr in attrs) {
			this.element.setAttribute(attr, attrs[attr]);
		}
		return this;
	}
	style(styles) {
		for (let style in styles) {
			this.element.style[style] = styles[style];
		}
		return this;
	}
	addEventListener(type, callback) {
		this.element.addEventListener(type, callback);
		return this;
	}
	get value() {
		return this.element.value;
	}
	set value(value) {
		this.element.value = value;
	}
}

function $(type) {
	return new El(type);
}
