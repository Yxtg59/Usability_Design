<script setup>
import { ref } from 'vue';
import axios from 'axios';
import { useRouter } from 'vue-router';

const form = ref({
  username: '',
  email: '',
  password: '',
  role: '',
  experience: ''
});

const errors = ref({
  username: '',
  email: '',
  password: '',
  role: '',
  experience: ''
});

const router = useRouter();

const handleRegister = async () => {
  errors.value = {};

  // Validaciones de campos de formulario existentes
  if (!form.value.username) {
    errors.value.username = 'El nombre de usuario es obligatorio.';
  }

  if (!form.value.email) {
    errors.value.email = 'El correo electrónico es obligatorio.';
  }

  if (!form.value.password) {
    errors.value.password = 'La contraseña es obligatoria.';
  }

  if (!form.value.role) {
    errors.value.role = 'El rol es obligatorio.';
  }

  if (form.value.role === 'evaluator' && !form.value.experience) {
    errors.value.experience = 'Debe seleccionar una experiencia.';
  }

  // Si hay errores, no enviar la solicitud
  if (Object.values(errors.value).some(error => error !== '')) {
    return;
  }

  try {
    // Envío de datos al backend
    const response = await axios.post('http://127.0.0.1:5000/register', {
      username: form.value.username,
      email: form.value.email,
      password: form.value.password,
      rol: form.value.role,
      experience: form.value.experience
    });

    console.log(response);

    router.push('/login'); // Redirige a la página de inicio de sesión después del registro
  } catch (error) {
    // Manejo de errores de la solicitud
    if (error.response && error.response.data) {
      // Asumimos que el backend devuelve errores en un formato específico
      errors.value = error.response.data.errors || {};
    } else {
      console.error(error);
    }
  }
};
</script>
<template>
  <div class="container">
    <div class="form-container"></div>
    <div>
      <h1 class="text-center">Registro de Usuario</h1>
      <div class="card">
        <div class="card-body">
          <form @submit.prevent="handleRegister">
            <div class="mb-3">
              <label for="username" class="form-label">Nombre de usuario</label>
              <input type="text" class="form-control" v-model="form.username" id="username">
              <div class="text-danger">{{ errors.username }}</div>
            </div>
            <div class="mb-3">
              <label for="email" class="form-label">Correo electrónico</label>
              <input type="email" class="form-control" v-model="form.email" id="email">
              <div class="text-danger">{{ errors.email }}</div>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Contraseña</label>
              <input type="password" class="form-control" v-model="form.password" id="password">
              <div class="text-danger">{{ errors.password }}</div>
            </div>
            <div class="mb-3">
              <label for="role" class="form-label">Rol</label>
              <select v-model="form.role" class="form-select" id="role">
                <option value="" disabled>Selecciona un rol</option>
                <option value="administrator">Administrador</option>
                <option value="owner">Propietario</option>
                <option value="evaluator">Evaluador</option>
              </select>
              <div class="text-danger">{{ errors.role }}</div>
            </div>
            <div v-if="form.role === 'evaluator'" class="mb-3">
              <label for="experience" class="form-label">Experiencia</label>
              <select v-model="form.experience" class="form-select" id="experience">
                <option value="" disabled>Selecciona tu experiencia</option>
                <option value="novato">Novato</option>
                <option value="experto">Experto</option>
              </select>
              <div class="text-danger">{{ errors.experience }}</div>
            </div>
            <button type="submit" class="btn btn-primary">Registrar Usuario</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
