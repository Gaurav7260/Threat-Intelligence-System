import streamlit as st


def login():

    st.title("🔐 SOC Analyst Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):

        if username == "admin" and password == "soc123":

            st.session_state["authenticated"] = True
            st.success("Login successful")
            st.rerun()

        else:
            st.error("Invalid credentials")