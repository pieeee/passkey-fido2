import React from "react";
import { createRoot } from "react-dom/client";
import { register, login } from "./webauthn";

const App = () => {
  const [username, setUsername] = React.useState("");

  return (
    <div>
      <h1>Passkey Authentication</h1>
      <input
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <button onClick={() => register(username)}>Register</button>
      <button onClick={() => login(username)}>Login</button>
    </div>
  );
};

const root = createRoot(document.getElementById("root"));
root.render(<App />);
