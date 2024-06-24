<script setup>
import { onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import axios from 'axios';

// Obtiene el ID de la prueba desde la ruta
const route = useRoute();
const testId = route.params.testId; 

// Datos del formulario y errores
const form = ref({
  title: '',
  description: '',
  url_frame: '',
  response_type: '',
});
const errors = ref({
  title: '',
  description: '',
  url_frame: '',
  response_type: '',
});

// Variables reactivas para la URL del test y tipo de test
const testUrl = ref(localStorage.getItem('testUrl'));
const testType = localStorage.getItem('testType');
const iframeStyle = ref({});
const containerStyle = ref({});
const questionnaires = ref([]);

// Al montar el componente, establece los estilos del iframe y actualiza la lista de cuestionarios
onMounted(async () => {
  setIframeStyles();
  await refreshQuestionnairesList();
});

// Establece los estilos del iframe según el tipo de prueba
const setIframeStyles = () => {
  if (testType === 'Movil') {
    iframeStyle.value = {
      width: '540px',
      height: '840px'
    };
    containerStyle.value = {
      width: '580px',
      height: '870px'
    };
  } else if (testType === 'Web') {
    iframeStyle.value = {
      width: '1146px',
      height: '942px'
    };
    containerStyle.value = {
      width: '1186px',
      height: '812px'
    };
  } else if (testType === 'Tablet') {
    iframeStyle.value = {
      width: '980px',
      height: '904px'
    };
    containerStyle.value = {
      width: '1020px',
      height: '944px'
    };
  }
};

// Actualiza la lista de cuestionarios
const refreshQuestionnairesList = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${testId}/questionnaires`);
    if (response.status === 200) {
      questionnaires.value = response.data;
    } else {
      questionnaires.value = [];
      console.error('No se encontraron cuestionarios.');
    }
  } catch (error) {
    questionnaires.value = [];
    console.error('Error al obtener los cuestionarios:', error);
  }
};

// Valida los datos del formulario antes de guardar
const validateForm = () => {
  errors.value = {
    title: '',
    description: '',
    url_frame: '',
    response_type: '',
  };
  if (!form.value.title) {
    errors.value.title = 'El Título del Cuestionario es obligatorio.';
  }
  if (!form.value.description) {
    errors.value.description = 'La Descripción es obligatoria.';
  }
  if (!form.value.url_frame) {
    errors.value.url_frame = 'La URL del Frame es obligatoria.';
  }
  if (!form.value.response_type) {
    errors.value.response_type = 'El Tipo de Respuesta es obligatorio.';
  }
  return !errors.value.title && !errors.value.description && !errors.value.url_frame && !errors.value.response_type;
};

// Maneja la acción de guardar un nuevo cuestionario
const handleSaveQuestionnaire = async () => {
  if (!validateForm()) {
    return;
  }
  try {
    const response = await axios.post(`http://127.0.0.1:5000/designtests/${testId}/questionnaires`, form.value);
    alert('Cuestionario creado exitosamente');
    form.value = {
      title: '',
      description: '',
      url_frame: '',
      response_type: '',
    };
    console.log(response)
    await refreshQuestionnairesList();
  } catch (error) {
    console.error('Error al crear el cuestionario:', error);
    alert('Error al crear el cuestionario');
  }
};

// Inicia la edición de un cuestionario
const startEditQuestionnaire = (questionnaire) => {
  questionnaire.isEditing = true;
};

// Cancela la edición de un cuestionario
const cancelEditQuestionnaire = (questionnaire) => {
  questionnaire.isEditing = false;
};

// Guarda los cambios en un cuestionario editado
const saveEditQuestionnaire = async (questionnaire) => {
  try {
    await axios.put(`http://127.0.0.1:5000/designtests/${testId}/questionnaires/${questionnaire.questionnaire_id}`, {
      title: questionnaire.title,
      description: questionnaire.description,
      url_frame: questionnaire.url_frame,
      response_type: questionnaire.response_type
    });
    alert('Cuestionario editado exitosamente');
    questionnaire.isEditing = false;
    await refreshQuestionnairesList();
  }catch (error) {
    console.error('Error al editar el cuestionario:', error);
    alert('Error al editar el cuestionario');
  }
};

// Maneja la eliminación de un cuestionario
const handleDeleteQuestionnaire = async (questionnaireId) => {
  if (!confirm('¿Estás seguro de que deseas eliminar este cuestionario?')) {
    return;
  }
  try {
    console.log(`Eliminando cuestionario con ID: ${questionnaireId}`);  // Debugging
    console.log(`URL: http://127.0.0.1:5000/designtests/${testId}/questionnaires/${questionnaireId}`);  // Debugging
    await axios.delete(`http://127.0.0.1:5000/designtests/${testId}/questionnaires/${questionnaireId}`);
    alert('Cuestionario eliminado exitosamente');
    await refreshQuestionnairesList();
  }catch (error) {
    console.error('Error al eliminar el cuestionario:', error);
    alert('Error al eliminar el cuestionario');
  }
};
</script>

<template>
  <div class="container mt-5 d-flex justify-content-center">
    <div class="d-flex justify-content-between align-items-start">
      <div class="card m-3" style="width: 600px;">
        <div class="card-header">
          <h1>Crear Cuestionario</h1>
        </div>
        <div class="card-body">
          <form @submit.prevent="handleSaveQuestionnaire">
            <div class="mb-3">
              <label for="title" class="form-label">Título del Cuestionario</label>
              <input v-model="form.title" type="text" class="form-control" id="title" :class="{ 'is-invalid': errors.title }"/>
              <div class="invalid-feedback">{{ errors.title }}</div>
            </div>
            <div class="mb-3">
              <label for="description" class="form-label">Descripción del Cuestionario</label>
              <textarea v-model="form.description" class="form-control" id="description" :class="{ 'is-invalid': errors.description }"></textarea>
              <div class="invalid-feedback">{{ errors.description }}</div>
            </div>
            <div class="mb-3">
              <label for="url_frame" class="form-label">URL del Frame</label>
              <input v-model="form.url_frame" type="text" class="form-control" id="url_frame" :class="{ 'is-invalid': errors.url_frame }"/>
              <div class="invalid-feedback">{{ errors.url_frame }}</div>
            </div>
            <div class="mb-3">
              <label for="response_type" class="form-label">Tipo de Respuesta</label>
              <select v-model="form.response_type" class="form-select" id="response_type" :class="{ 'is-invalid': errors.response_type }">
                <option value="Calificación">Calificación</option>
                <option value="Legibilidad">Legibilidad</option>
                <option value="Coherencia">Coherencia</option>
              </select>
              <div class="invalid-feedback">{{ errors.response_type }}</div>
            </div>
            <button type="submit" class="btn btn-primary">Crear Cuestionario</button>
          </form>
        </div>
      </div>
      <div class="container">
        <div class="card p-3" ref="iframeContainer" :style="containerStyle">
          <iframe :src="testUrl" :style="iframeStyle" allowfullscreen></iframe>
        </div>
      </div>
    </div>
  </div>

  <div class="m-5">
    <div class="card-body" v-if="questionnaires.length > 0">
      <p class="card-title m-3" style="text-align:center; "><strong>Cuestionarios</strong></p>
      <div v-for="questionnaire in questionnaires" :key="questionnaire.questionnaire_id" class="mb-3 d-flex">
        <div class="card me-3" style="width: 25%;">
          <div class="card-body">
            <div v-if="!questionnaire.isEditing">
              <p class="card-title"><strong>Título: </strong>{{questionnaire.title}}</p>
              <p class="card-description"><strong>Descripción: </strong>{{questionnaire.description}}</p>
              <p class="card-response_type"><strong>Tipo de Respuesta: </strong>{{questionnaire.response_type}}</p>
              <button @click="startEditQuestionnaire(questionnaire)" class="btn btn-warning me-2">Editar</button>
              <button @click="handleDeleteQuestionnaire(questionnaire.questionnaire_id)" class="btn btn-danger">Eliminar</button>
            </div>
            <div v-else>
              <div class="mb-3">
                <label for="editTitle" class="form-label">Título del Cuestionario</label>
                <input v-model="questionnaire.title" type="text" class="form-control" id="editTitle"/>
              </div>
              <div class="mb-3">
                <label for="editDescription" class="form-label">Descripción del Cuestionario</label>
                <textarea
                  v-model="questionnaire.description"
                  class="form-control"
                  id="editDescription"
                ></textarea>
              </div>
              <div class="mb-3">
                <label for="editUrlFrame" class="form-label">URL del Frame</label>
                <input v-model="questionnaire.url_frame" type="text" class="form-control" id="editUrlFrame"/>
              </div>
              <div class="mb-3">
                <label for="editResponseType" class="form-label">Tipo de Respuesta</label>
                <select v-model="questionnaire.response_type" class="form-select" id="editResponseType">
                  <option value="Calificación">Calificación</option>
                  <option value="Legibilidad">Legibilidad</option>
                  <option value="Coherencia">Coherencia</option>
                </select>
              </div>
              <button @click="saveEditQuestionnaire(questionnaire)" class="btn btn-success me-2">Guardar</button>
              <button @click="cancelEditQuestionnaire(questionnaire)" class="btn btn-secondary">Cancelar</button>
            </div>
          </div>
        </div>
        <div class="card" style="width: 75%;">
          <div class="card-body">
            <iframe v-if="!questionnaire.isEditing" :src="questionnaire.url_frame" width="100%" height="900" frameborder="0"></iframe>
          </div>
        </div>
      </div>
      </div>
  </div>
</template>

<style scoped>
.container {
  max-width: 1920px;
}
.me-3 {
  margin-right: 1rem;
}
.card-title {
  font-size: 1.5rem;
  font-weight:450;
}

.card-description, .card-response_type {
  font-size: 1.2rem;
  font-weight: 350;
}
.d-flex {
  display: flex;
}
.btn {
  padding: 0.5rem 1rem;
  font-size: 1rem;
}
.text-center {
  text-align: center;
}
</style>
