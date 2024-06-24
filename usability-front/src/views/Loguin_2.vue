<script setup>
import { ref } from 'vue';
import axios from 'axios';
import { useRouter } from 'vue-router';
import { useAuthStore } from '../stores/useAuthStore';

const form = ref({
  username: '',
  password: ''
});

const errors = ref({
  username: '',
  password: ''
});

const useAuth = useAuthStore();
const router = useRouter();

const handleLogin = async () => {
  errors.value = {};

  if (!form.value.username) {
    errors.value.username = 'El nombre de usuario es obligatorio.';
  }

  if (!form.value.password) {
    errors.value.password = 'La contraseña es obligatoria.';
  }

  if (Object.values(errors.value).some(error => error !== '')) {
    return;
  }

  try {
    const response = await axios.post('http://127.0.0.1:5000/login', {
      username: form.value.username,
      password: form.value.password
    });

    const rol = response.data.user.rol;
    let experience = '';

    // Verificar si el rol es 'evaluador' y obtener la experiencia
    if (rol === 'evaluador') {
      experience = response.data.user.experience;
    }

    // Iniciar sesión con el rol y la experiencia correspondientes
    useAuth.login(rol, experience);

    router.push('/pruebasheuristicas'); 
    
    // Redirigir a la página correspondiente basada en el rol
    // if (rol === 'evaluator') {
    //     router.push('/DesingTestEvaluation');
    //   } else if (rol === 'owner') {
    //     router.push('/pruebadiseno');
    //   } else {
    //     console.error('Invalid role');
    //   }


    if (response.data.user) {
      localStorage.setItem('user_id', response.data.user.id);
    }
  
  } catch (error) {
    if (error.response && error.response.data) {
      errors.value = error.response.data.errors || {};
    } else {
      console.error(error);
    }
  }
};
</script>

<template>
  <div class="login-container m-3">
    <div class="login-form">
      <div class="d-flex justify-content-center mb-4">
        <img src="../assets/lading/imagen2.png" alt="Logo de la empresa" class="logo">
      </div>
      <h1 class="text-center">Iniciar Sesión</h1>
      <form @submit.prevent="handleLogin" class="form">
        <div class="form-group">
          <label for="username" class="form-label">Nombre de usuario</label>
          <input type="text" class="form-control" v-model="form.username" id="username">
          <div class="text-danger">{{ errors.username }}</div>
        </div>
        <div class="form-group">
          <label for="password" class="form-label">Contraseña</label>
          <input type="password" class="form-control" v-model="form.password" id="password">
          <div class="text-danger">{{ errors.password }}</div>
        </div>
        <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
      </form>
    </div>
  </div>
</template>

<style scoped>
.logo {
  max-width: 100%;
  height: auto;
}
</style>